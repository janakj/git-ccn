/*
 * Server for exporting git repositories via CCNx
 *
 * Copyright (C) 2010-2011 Jan Janak <jan@ryngle.com>
 *
 * This work is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License version 2 as published by the
 * Free Software Foundation. This work is distributed in the hope that it will
 * be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
 * Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <ccn/ccn.h>
#include <ccn/uri.h>
#include <ccn/reg_mgmt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <limits.h>
#include <errno.h>
#include "strbuf.h"
#include "cache.h"
#include "refs.h"
#include "object.h"
#include "tag.h"


#define STR_INIT(v) {(v), sizeof(v) - 1}

/* Format of location information. Includes the pid of the process, filename,
 * function name, and line number. */
#define LOC_FMT "[%d:%s:%s:%d]"
#define LOC_FMT_LEN (sizeof(LOC_FMT) - 1)

/* Format of timestamps printed to standard or error outputs. */
#define TIME_FMT "%b-%d %H:%M:%S"
#define TIME_FMT_LEN 15 /* The length of the resulting string */

/* Make sure __func__ macro is defined. This macro is available in C99, but
 * older gcc versions provided __FUNCTION__. */
#if __STDC_VERSION__ < 199901L
#    if __GNUC__ >= 2
#        define __func__ __FUNCTION__
#    else
#        define __func__ "?"
#    endif
#endif

/* Define NO_LOG globally if you want to compile the program without any
 * logging code. This is useful for profiling. */
#ifdef NO_LOG
#    define _LOG(priority, stream, prefix, msg, args...)
#else
#    define _LOG(priority, stream, prefix, msg, args...)                \
    do {                                                                \
        if (log_level >= priority) {                                    \
            if (log_syslog)                                             \
                if (log_level >= LOG_DEBUG)                             \
                    syslog(priority, LOC_FMT prefix ": " msg,           \
                           getpid(), __FILE__, __func__, __LINE__,      \
                           ## args);                                    \
                else                                                    \
                    syslog(priority, "[%d]" prefix ": " msg,            \
                           getpid(), ## args);                          \
            else {                                                      \
                if (log_level >= LOG_DEBUG)                             \
                    fprintf(stream,                                     \
                            "%s " LOC_FMT prefix ": " msg "\n",         \
                            _gettime(),                                 \
                            getpid(), __FILE__, __func__, __LINE__,     \
                            ## args);                                   \
                else                                                    \
                    fprintf(stream, "%s [%d]" prefix ": " msg "\n",     \
                            _gettime(), getpid(), ## args);             \
            }                                                           \
        }                                                               \
    } while(0)
#endif

#define DBG(msg, args...) _LOG(LOG_DEBUG, stdout, " DEBUG", msg, ## args)
#define INF(msg, args...) _LOG(LOG_INFO, stdout, "", msg, ## args)
#define WARN(msg, args...) _LOG(LOG_WARNING, stderr, " WARNING", msg, ## args)
#define ERR(msg, args...) _LOG(LOG_ERR, stderr, " ERROR", msg, ## args)


static char *prefix_str = "/git";
static struct ccn_charbuf *prefix;

/* This is the root of all git repositories exported via CCN by gitd. For
 * example, with default configuration, when git receives an Interest with
 * name prefix "/git/linux", it will search for a git repository in
 * "/srv/git/linux" and export its contents via CCNx. */
static char *repo_root = "/git";

static char help_msg[] = "\
Usage: git-ccnx [options]\n\
Options:\n\
    -h       This help text.\n\
    -v       Increase verbosity (Use repeatedly to increase more).\n\
    -E       Write log messages to standard output instead of syslog.\n\
    -p name  CCNx name prefix to register with ccnd.\n\
    -r dir   Top-level directory with Git repositories.\n\
";

/* If set to 1 write messages to syslog. If 0 write them to standard and error
 * outputs. */
static int log_syslog = 1;
static int log_level = LOG_WARNING;

/* CCN forwarding link in the parent process, this link forwards Interest
 * packets with the prefix common for all git repositories. */
static struct ccn *parent_link;

/* CCN forwarding link in a child process, this link forwards Interest packets
 * with the prefix for only one repository handled by the child process. */
static struct ccn *child_link;

/* A list of special files from the git repository that can be served
 * directly. */
static struct {
    char *name;
    size_t len;
} specials[] = {
    STR_INIT("HEAD"),
    STR_INIT("description"),
    STR_INIT("info/refs"),
    STR_INIT("objects/info/packs"),
    {NULL, 0}};


/* Returns text representation of current date and time. Only current month,
 * day and time down to a second are printed. This is used when logging to the
 * standard output. Returns empty string on error. */
static inline const char *
_gettime(void)
{
    static char buf[TIME_FMT_LEN + 1];
    time_t t;
    struct tm *tmp;

    t = time(NULL);
    if (!(tmp = localtime(&t))
        || strftime(buf, TIME_FMT_LEN + 1, TIME_FMT, tmp) != TIME_FMT_LEN)
        *buf = '\0';
    return buf;
}


void
start_logger(void)
{
    if (log_syslog)
        openlog("git-ccnx", LOG_CONS, LOG_DAEMON);
}


void
stop_logger(void)
{
    if (log_syslog)
        closelog();
}


/* Increase log level. We only use three discrete syslog values, errors, info,
 * and debug. */
void
inc_log_level(void)
{
    switch(log_level) {
    case LOG_ERR:
        log_level = LOG_WARNING;
        break;

    case LOG_WARNING:
        log_level = LOG_INFO;
        break;

    case LOG_INFO:
        log_level = LOG_DEBUG;
        break;
    }
}


static void
stop_ccn_forwarding(struct ccn **c)
{
    if (c && *c) {
        ccn_disconnect(*c);
        ccn_destroy(c);
        c = NULL;
    }
}


/* Create a new connection to the local ccnd instance and setup the forwarding
 * so that Interest packets with "prefix" get delivered to "handler". */
static struct ccn*
setup_ccn_forwarding(struct ccn_charbuf *prefix, ccn_handler handler)
{
    struct ccn_closure *cl = NULL;
    struct ccn *c = NULL;

    if (!(cl = (struct ccn_closure *)calloc(1, sizeof(struct ccn_closure))))
        goto error;
    cl->p = handler;

    if ((c = ccn_create()) == NULL)
        goto error;
    if (ccn_connect(c, NULL) < 0)
        goto error;

    /* We cannot call the simpler ccn_set_interest_filter here because that
     * function sets CCN_FORW_CHILD_INHERIT flag that says that the entry may
     * be used even if there's a longer match available. Since we explicitly
     * rely on the longer-prefix match to deliver Interests to correct process
     * children, we have to make sure that the flag isn't set. */
    if (ccn_set_interest_filter_with_flags(c, prefix, cl, CCN_FORW_ACTIVE) < 0)
        goto error;

    return c;

error:
    ERR("Failed to setup forwarding.");
    if (c)
        ccn_disconnect(c);
    ccn_destroy(&c);
    if (cl)
        free(cl);
    return NULL;
}


/* Because we currently have no way of passing the target of a symref to the
 * append_ref function, we store it temporarily in a global variable for the
 * function to pick up. */
static const char *symref;

static int
append_ref(const char *ref, const unsigned char *sha1, int flag, void *output)
{
    struct object *o;
    struct ccn_charbuf *buf = (struct ccn_charbuf *)output;
    int res = 0;

    /* Make sure this is aligned with the ref_entry structure in
     * remote-ccnx.c. The SHA1, ref_name and symref strings are appended right
     * after this structure in the output buffer. */
    struct ref_entry {
        unsigned int flags;
        unsigned int ref_len;
        unsigned int symref_len;
    } e;

    if (!buf || (!(o = parse_object(sha1))))
        return -1;

    e.flags = htonl(flag);
    e.ref_len = htonl(strlen(ref));
    e.symref_len = htonl(symref ? strlen(symref) : 0);

    /* Here we're inventing our own format for the list of all references.
     * Each record starts with the flag field, followed by the length of the
     * name of the ref, followed by the length of the target of the symref (if
     * any). That way all fixed size elements are at the beginning of the data
     * structure and we won't have problems with alignment. The 20-byte SHA1
     * follows the structure, followed by the ref_len+1 bytes of ref_name and
     * symref_len+1 bytes of symref. Both strings are zero-terminated but the
     * terminators are not included in ref_len and symref_len. The symref is
     * currently only used for the HEAD ref, because for other refs we don't
     * get the target of the symref from the caller (to be fixed). */
    res |= ccn_charbuf_append(buf, &e, sizeof(struct ref_entry));
    res |= ccn_charbuf_append(buf, sha1, 20);
    res |= ccn_charbuf_append(buf, ref, ntohl(e.ref_len) + 1);
    res |= ccn_charbuf_append(buf, symref ? symref : "\0",
                              ntohl(e.symref_len) + 1);

    if (!res && o->type == OBJ_TAG && (o = deref_tag(o, ref, 0))) {
        /* This is a tag object and we found its non-tag target. Add it as
         * another ref with "^{}" appended to its name. This is used by
         * clients to resolve and synchronize remote tags. */
        struct strbuf tmp = STRBUF_INIT;
        strbuf_init(&tmp, ntohl(e.ref_len) + 4);
        strbuf_add(&tmp, ref, ntohl(e.ref_len));
        strbuf_add(&tmp, "^{}", 4); /* 4 includes '\0' at the end */
        res |= append_ref(tmp.buf, o->sha1, 0, output);
        strbuf_release(&tmp);
    }
    return res;
}


static struct ccn_charbuf *
get_reflist(void)
{
    unsigned char sha1[20];
    struct ccn_charbuf *out = NULL;
    int flag;

    if (!(out = ccn_charbuf_create()))
        goto error;

    /* FIXME: This was taken from remote-curl.c, but we might need a better
     * algorithm for obtaining the list of all refs so that we can preserve
     * symrefs and their targets in the list and pass that all the way to the
     * client. Currently we do that for HEAD in a hackish way. */
    if (for_each_ref(append_ref, out))
        goto error;

    if ((symref = resolve_ref("HEAD", sha1, 1, &flag)))
        if (append_ref("HEAD", sha1, flag, out))
            goto error;

    goto out;
error:
    ccn_charbuf_destroy(&out);
out:
    symref = NULL;
    if (!out)
        ERR("Failed to generate refs list.");
    return out;
}


/* Load the contents of the file in name into a ccn_charbuf */
static int
load_file(struct ccn_charbuf **dst, const char *name)
{
    struct ccn_charbuf *res = NULL;
    FILE *f;
    unsigned char *p;
    int r;

    if (!(f = fopen(name, "r")))
        return 1;
    if (!(res = ccn_charbuf_create()))
        goto error;

    do {
        if (!(p = ccn_charbuf_reserve(res, 256)))
            goto error;
        r = fread(p, 1, 256, f);
        if (r == 0 && ferror(f)) {
            ERR("Error while reading file '%s'", name);
            goto error;
        } else if (r > 0)
            res->length += r;
    } while(r);

    fclose(f);
    *dst = res;
    return 0;

error:
    ccn_charbuf_destroy(&res);
    fclose(f);
    return -1;
}


/* This function is CCN Interest handler. It is called whenever ccnd receives
 * a matching Interest packet. The function is supposed to handle the Interest
 * and produce corresponding Data. */
static enum ccn_upcall_res
child_handler(struct ccn_closure *selfp, enum ccn_upcall_kind kind,
              struct ccn_upcall_info *info)
{
    const unsigned char *op;
    size_t op_len;
    enum ccn_upcall_res res = CCN_UPCALL_RESULT_OK;
    struct ccn_charbuf *body = NULL, *data = NULL, *dname = NULL;
    struct ccn_signing_params sp = CCN_SIGNING_PARAMS_INIT;
    unsigned int b, e, i, v, comps_left;
    void *obj = NULL;

    sp.freshness = 10;
    switch(kind) {
    case CCN_UPCALL_FINAL:
        free(selfp);
    case CCN_UPCALL_CONSUMED_INTEREST:
        goto out;
    case CCN_UPCALL_INTEREST:
        break;
    default:
        goto error;
    }

    /* -1 to ignore the final digest component that is present in every
        Interest prefix */
    comps_left = info->interest_comps->n - info->matched_comps - 1;
    if (comps_left < 1)
        goto out;
    if (ccn_name_comp_get(info->interest_ccnb, info->interest_comps,
                          info->matched_comps, &op, &op_len) < 0) {
        ERR("Error while extrating git operation from prefix.");
        goto error;
    }

    /* Create Data packet buffers */
    data = ccn_charbuf_create();
    dname = ccn_charbuf_create();
    if (!data || !dname) {
        ERR("Memory allocation failure.\n");
        goto error;
    }

    b = info->pi->offset[CCN_PI_B_Name];
    e = info->pi->offset[CCN_PI_E_ComponentLast];
    ccn_charbuf_append(dname, info->interest_ccnb + b, e - b);
    ccn_charbuf_append_closer(dname);

    if (comps_left == 1 && op_len == 4
        && !strncmp((char*)op, "refs", op_len)) {
        /* Return the list of all refs from the repository */
        if (!(body = get_reflist()))
            goto error;
    } else if (comps_left == 2 && op_len == 7
               && !strncmp((char*)op, "objects", op_len)) {
        /* Lookup the object with the given SHA1 and return it */
        unsigned char sha1[20];
        const unsigned char* hex;
        enum object_type type;
        size_t len;

        /* FIXME: We should switch to binary representation of SHA1, once I
         * figure out how to encode it safely into components */
        v = ccn_name_comp_get(info->interest_ccnb, info->interest_comps,
                              info->matched_comps + 1, &hex, &len);
        if (v < 0 || len != 40)
            goto out;
        if (get_sha1_hex((const char*)hex, sha1) != 0)
            goto out;
        if (!(obj = read_sha1_file_repl(sha1, &type, &len, NULL)))
            goto out;
        if (!(body = ccn_charbuf_create())) {
            ERR("Memory allocation failure");
            goto error;
        }
        if (ccn_charbuf_append(body, obj, len) < 0) {
            ERR("Can't copy object");
            goto error;
        }
    } else if (comps_left == 1){
        /* Serve special files from the git repository */
        for(i = 0; specials[i].name; i++) {
            if (op_len == specials[i].len
                && !strncmp((char*)op, specials[i].name, op_len)) {
                v = load_file(&body, specials[i].name);
                if (v > 0)
                    goto out; /* File not found */
                else if (v < 0)
                    goto error; /* Error reading file */
                break;
            }
        }
    }

    /* If the functions above produced content, even empty, sign it */
    if (!body) goto out;
    if (ccn_sign_content(info->h, data, dname, &sp,
                         body->buf, body->length) < 0)
        goto error;

    if (data->length > 65535) {
        INF("Object may be too big to send in one piece: %lu", data->length);
    }

    if (ccn_put(info->h, data->buf, data->length) < 0)
        goto error;
    res = CCN_UPCALL_RESULT_INTEREST_CONSUMED;

    goto out;
error:
    res = CCN_UPCALL_RESULT_ERR;
out:
    if (obj)
        free(obj);
    ccn_charbuf_destroy(&body);
    ccn_charbuf_destroy(&data);
    ccn_charbuf_destroy(&dname);
    return res;
}


/* This function is CCN Interest handler. It is called whenever ccnd receives
 * a matching Interest packet. The function is supposed to handle the Interest
 * and produce corresponding Data. */
static enum ccn_upcall_res
parent_handler(struct ccn_closure *selfp, enum ccn_upcall_kind kind,
               struct ccn_upcall_info *info)
{
    int res = CCN_UPCALL_RESULT_OK;
    pid_t child;
    struct strbuf path = STRBUF_INIT;
    const unsigned char *repo;
    size_t len;

    switch(kind) {
    case CCN_UPCALL_FINAL:
        free(selfp);
    case CCN_UPCALL_CONSUMED_INTEREST:
        goto out;
    case CCN_UPCALL_INTEREST:
        break;
    default:
        goto error;
    }
    /* Check if it is OK to produce new data */
    if (!(info->pi->answerfrom & CCN_AOK_NEW))
        goto out;

    /* Make sure we received git repository name in Interest's prefix. */
    if (info->matched_comps >= info->interest_comps->n) {
        ERR("Prefix does not contain git repository name.");
        goto error;
    }

    if (ccn_name_comp_get(info->interest_ccnb, info->interest_comps,
                          info->matched_comps,
                          &repo, &len) < 0) {
        ERR("Error while extrating git repository name from prefix.");
        goto error;
    }

    /* We're in the parent process and we received a request for a repository
     * for which we have no child yet (otherwise the Interest would have been
     * forwarded to the child). Before proceeding to the expensive fork, make
     * sure that the git repository exists and appears to be usable. */
    strbuf_init(&path, PATH_MAX);
    strbuf_addstr(&path, repo_root);
    strbuf_addch(&path, '/');
    strbuf_add(&path, repo, len);

    /* Try the directory as a bare git repository first. If it does not look
     * like a bare repository, try the ".git" sub-directory instead. */
    if (!is_git_directory(path.buf)) {
        strbuf_addstr(&path, "/.git");
        if (!is_git_directory(path.buf))
            goto error;
    }

    /* We're in the parent process here. This is the process that registers
     * Interests for the general prefix common for all git repositories. The
     * goal of this process is only to create a new child process and pass the
     * Interest packet to it. The child process will then generate the
     * corresponding Data packet and send it to ccnd over its own forwarding
     * link. This magic is necessesary for git code to function properly. Most
     * git functions die by exiting the process when something goes wrong, so
     * we have to execute them in a process of their own to make sure that the
     * main daemon continues functioning. Also, once the process initializes a
     * git repository, it's probably not possible (or at least easy) to
     * reinitialize it. Hence one process can handle only one git repository.
     */
    child = fork();
    if (child == -1) {
        ERR("Can't create a child process: %s", strerror(errno));
        goto error;
    } else if (child == 0) {
        /* Here comes a new child, pure and innocent. We need to setup a new
         * link to ccnd here, to avoid sharing the link inherited from the
         * parent. We do not disconnect the link to ccnd inherited from the
         * parent, the parent process is still using it and will take care of
         * it. */
        ccn_name_append(prefix, repo, len);

        if (!(child_link = setup_ccn_forwarding(prefix, child_handler))) {
            ERR("Failed to setup ccn forwarding.");
            exit(EXIT_FAILURE);
        }

        if (chdir(path.buf) < 0) {
            ERR("Can't enter directory '%s': %s\n", path.buf, strerror(errno));
            exit(EXIT_FAILURE);
        }
        setup_git_directory();

        while(1)
            if (ccn_run(child_link, -1) < 0) {
                ERR("Error in event loop in a child process");
                goto error;
            }

        stop_ccn_forwarding(&child_link);
        exit(EXIT_SUCCESS);
    }

    goto out;
error:
    res = CCN_UPCALL_RESULT_ERR;
out:
    strbuf_release(&path);
    return res;
}


static void
sig_child(int signo)
{
    int status, child_val;

    if (waitpid(-1, &status, WNOHANG) < 0)
        return;
    if (WIFEXITED(status)) {
        child_val = WEXITSTATUS(status);
    }
}


int
main(int argc, char *argv[])
{
    int res = EXIT_SUCCESS, opt;

    start_logger();
    while((opt = getopt(argc, argv, "hp:r:vE")) != -1) {
        switch(opt) {
        case 'h':
            fprintf(stdout, "%s", help_msg);
            exit(EXIT_SUCCESS);
            break;
        case 'p':
            if (!(prefix_str = strdup(optarg)))
                abort();
            break;
        case 'r':
            if (!(repo_root = strdup(optarg)))
                abort();
            break;
        case 'v':
            inc_log_level();
            break;
        case 'E':
            log_syslog = 0;
            break;
        default:
            fprintf(stderr, "Use the -h option for list of supported "
                    "program arguments\n");
            exit(EXIT_FAILURE);
        }
    }

    printf("CCNx Git Server for CCNx API v%d, built on "
           __DATE__ " " __TIME__ "\n",
           CCN_API_VERSION);

    if (!(prefix = ccn_charbuf_create()))
        goto error;
    if (ccn_name_from_uri(prefix, prefix_str) < 0)
        goto error;
    if (!(parent_link = setup_ccn_forwarding(prefix, parent_handler)))
        goto error;

    if (signal(SIGCHLD, sig_child) == SIG_ERR) {
        ERR("Can't setup SIGCHLD handler.");
        goto error;
    }

    while(1) {
        if (ccn_run(parent_link, -1) < 0) {
            ERR("Error in ccn_run in dispatcher process");
            goto error;
        }
    }

    goto out;
error:
    res = EXIT_FAILURE;
out:
    stop_ccn_forwarding(&parent_link);
    ccn_charbuf_destroy(&prefix);
    stop_logger();
    exit(res);
}
