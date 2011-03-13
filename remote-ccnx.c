#include "git-compat-util.h"
#include "cache.h"
#include "remote.h"
#include "strbuf.h"
#include "walker.h"
#include "exec_cmd.h"
#include "run-command.h"
#include "pkt-line.h"
#include "sideband.h"
#include <ccn/ccn.h>
#include <ccn/uri.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/stat.h>


#define IS_BLANK(c) ((c) == ' ' || (c) == '\t')

#define OPT_CMD "option"
#define OPT_CMD_LEN (sizeof(OPT_CMD) - 1)

#define LIST_CMD "list"
#define LIST_CMD_LEN (sizeof(LIST_CMD) - 1)

#define FETCH_CMD "fetch"
#define FETCH_CMD_LEN (sizeof(FETCH_CMD) - 1)

/* CCNx library handle */
static struct ccn *ccnx;

/* The handle for the remote repositor */
static struct remote *remote;

/* The URL of the remote repository */
static const char *url;
/* CCNx prefix created from the URL */
static struct ccn_charbuf *prefix;

static struct options {
    int verbosity;
    unsigned long depth;
    unsigned progress : 1,
        followtags : 1,
        dry_run : 1,
        thin : 1;
} options;

/* Make sure this is aligned with the ref_entry structure in ccnx.c. */
struct ref_entry {
    unsigned int flags;
    unsigned int ref_len;
    unsigned int symref_len;
    unsigned char sha1[20];
    char ref[0];
};

struct walker_data {
    struct ccn *ccnx;
    struct ccn_charbuf *prefix;
};


static int
parse_bool_option(int *res, char *str)
{
    if (!*str)
        /* Missing option value means true */
        *res = 1;
    else if (!strcasecmp(str, "true")
        || !strcasecmp(str, "yes"))
        *res = 1;
    else if (!strcasecmp(str, "false")
             || !strcasecmp(str, "no"))
        *res = 0;
    else
        return 0;

    return 1;
}


static int
parse_int_option(int *res, char *str)
{
    long v;
    char *end;

    errno = 0;
    v = strtol(str, &end, 0);
    if ((errno == ERANGE && (v == LONG_MIN || v == LONG_MAX))
        || (errno && !v) /* Some other error */
        || (str == end) /* Nothing parsed */
        || (*end && !IS_BLANK(*end)) /* Un-parsed value suffix */
        || (v < INT_MIN || v > INT_MAX)) { /* Integer over/under-flow */
        return 0;
    }

    *res = v;
    return 1;
}


static int
parse_ulong_option(unsigned long *res, char *str)
{
    unsigned long v;
    char *end;

    errno = 0;
    v = strtoul(str, &end, 0);
    if ((errno == ERANGE && v == LONG_MAX) /* Overflow */
        || (errno && !v) /* Some other error */
        || (str == end) /* Nothing parsed */
        || (*end && !IS_BLANK(*end))) { /* Un-parsed value suffix */
        return 0;
    }

    *res = v;
    return 1;
}


static int
option(struct strbuf *cmd)
{
    char *value, *name = cmd->buf + OPT_CMD_LEN;
    int v;

    /* Skip white space */
    while(*name && IS_BLANK(*name))
        name++;
    if (!*name) {
        printf("unsupported\n");
        return -1;
    }
    value = name;
    while(*value && !IS_BLANK(*value))
        value++;
    /* Zero-terminate option name if needed */
    if (IS_BLANK(*value))
        *value++ = '\0';

    /* Skip white space delimiting option name and option value */
    while(*value && IS_BLANK(*value))
        value++;

    if (!strcmp(name, "verbosity")) {
        if (!parse_int_option(&options.verbosity, value))
            goto errval;
    } else if (!strcmp(name, "progress")) {
        if (!parse_bool_option(&v, value))
            goto errval;
        options.progress = v;
    } else if (!strcmp(name, "depth")) {
        if (!parse_ulong_option(&options.depth, value))
            goto errval;
    } else if (!strcmp(name, "followtags")) {
        if (!parse_bool_option(&v, value))
            goto errval;
        options.followtags = v;
    } else if (!strcmp(name, "dry-run")) {
        if (!parse_bool_option(&v, value))
            goto errval;
        options.dry_run = v;
    } else {
        printf("unsupported\n");
        return 1;
    }

    printf("ok\n");
    return 0;

errval:
    printf("error Invalid option value '%s' for option '%s'.\n", value, name);
    return -1;
}


static int
list(struct strbuf *cmd)
{
    int rv = 0, i;
    size_t len;
    struct ccn_charbuf *res = NULL, *name = NULL;
    const unsigned char *ptr, *orig;
    struct ccn_parsed_ContentObject content = {0};
    struct ccn_indexbuf *refs = NULL;
    struct ref_entry *e;

    /* Create the Interest prefix for the list of refs */
    if (!(name = ccn_charbuf_create()))
        goto error;
    if (ccn_charbuf_append_charbuf(name, prefix) < 0)
        goto error;
    if (ccn_name_append_str(name, "refs") < 0)
        goto error;

    if (!(res = ccn_charbuf_create()))
        goto error;

    len = 0;
    if (ccn_get(ccnx, name, NULL, 3000, res,
                &content, NULL, CCN_GET_NOKEYWAIT) >= 0)
        ccn_content_get_value(res->buf, res->length, &content, &ptr, &len);
    if (len == 0)
        goto out;

    if (!(refs = ccn_indexbuf_create()))
        goto error;
    orig = ptr;

    while(len) {
        if (len < sizeof(struct ref_entry))
            goto error;

        e = (struct ref_entry *)ptr;
        e->flags = ntohl(e->flags);
        e->ref_len = ntohl(e->ref_len);
        e->symref_len = ntohl(e->symref_len);

        if (len < (e->ref_len + e->symref_len + 2))
            goto error;

        if (ccn_indexbuf_append_element(refs, ptr - orig) < 0)
            goto error;

        ptr += sizeof(struct ref_entry) + e->ref_len + e->symref_len + 2;
        len -= sizeof(struct ref_entry) + e->ref_len + e->symref_len + 2;
    }

    /* FIXME: We should make sure here that all symrefs can be resolved before
     * printing everything */

    for(i = 0; i < refs->n; i++) {
        e = (struct ref_entry*)(orig + refs->buf[i]);
        if (e->symref_len)
            printf("@%s %s\n", e->ref + e->ref_len + 1, e->ref);
        else
            printf("%s %s\n", sha1_to_hex(e->sha1), e->ref);
    }

    printf("\n");
    fflush(stdout);

    goto out;
error:
    fprintf(stderr, "Can't obtain refs list.\n");
    rv = -1;
out:
    ccn_indexbuf_destroy(&refs);
    ccn_charbuf_destroy(&res);
    ccn_charbuf_destroy(&name);
    return rv;
}


/* FIXME:
 * - Inflate the object, recompute the SHA1 and check it here
 */
static int
save_deflated_object(const unsigned char *buf, size_t len,
                     unsigned char *sha1)
{
    char *path, *sep, tmp[PATH_MAX];
    int fd = -1, res = 0, n = 0;
    ssize_t rv;

    /* Check if, by any chance, the object appeared in the local database
     * somehow. */
    if (has_sha1_file(sha1))
        goto out;

    /* Fetch the object data here */

    /* Open the local temporary file for loose object. */
    path = sha1_file_name(sha1);
    snprintf(tmp, sizeof(tmp), "%s.temp", path);
    unlink_or_warn(tmp);

    fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL, 0666);
    if (fd < 0 && errno == ENOENT) {
        /* The local cache directory may not exist yet, try to create it. */
        if ((sep = strrchr(tmp, '/'))) {
            *sep = '\0';
            if (mkdir(tmp, 0777) < 0) {
                fprintf(stderr, "fatal: Couldn't create directory %s: %s\n",
                        tmp, strerror(errno));
                goto error;
            }
            *sep = '/';
            fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL, 0666);
        }
    }
    if (fd < 0) {
        fprintf(stderr, "fatal: Couldn't create file '%s': %s\n",
                tmp, strerror(errno));
        goto error;
    }

    /* Write the compressed object into the temporary file. */
    while (n < len) {
        if ((rv = xwrite(fd, buf + n, len - n)) < 0) {
            fprintf(stderr, "fatal: Can't write object: %s\n",
                    strerror(errno));
            goto error;
        }
        n += rv;
    }

    /* Move the temporary file to the correct place. */
    if (move_temp_to_file(tmp, path) < 0)
        goto error;

    goto out;
error:
    res = -1;
    unlink_or_warn(tmp);
out:
    close(fd);
    return res;
}


static int
fetch_object(struct walker *w, unsigned char *sha1)
{
    int res = 0;
    size_t len = 0;
    struct walker_data *d = w->data;
    const unsigned char *ptr;
    struct ccn_charbuf *buf = NULL;
    struct ccn_parsed_ContentObject content = {0};

    /* Replace the SHA1 placeholder in the prefix with actual SHA1 of the
     * object we want to fetch. */
    memcpy(d->prefix->buf + d->prefix->length - 40 - sizeof(CCN_CLOSE) * 2,
           sha1_to_hex(sha1), 40);

    if (!(buf = ccn_charbuf_create()))
        goto error;
    if (ccn_get(d->ccnx, d->prefix, NULL, 3000, buf, &content, NULL,
                CCN_GET_NOKEYWAIT) >= 0)
        ccn_content_get_value(buf->buf, buf->length, &content, &ptr, &len);
    if (len == 0
        || save_deflated_object(ptr, len, sha1) == 0)
        goto out;

error:
    res = -1;
out:
    ccn_charbuf_destroy(&buf);
    return res;
}


static void
cleanup(struct walker *w)
{
    struct walker_data *data = w->data;

    if (data) {
        ccn_charbuf_destroy(&data->prefix);
        free(data);
    }
}


static void
prefetch(struct walker *w, unsigned char *sha1)
{
    /* Here we need to implement a queue of fetch requests and start fetching
     * them in a stream-lined manner as soon as requests are added to the
     * queue to speed things up. At any given time the tree walker can yield a
     * number of objects that are missing in the repository and will be needed
     * while traversing the DAG. */
}


/* Create a new walker data structure. This function exists on failure and
 * never returns NULL */
static struct walker *
get_ccnx_walker(const struct ccn_charbuf *prefix)
{
    char closer[] = {CCN_CLOSE, CCN_CLOSE};
    struct walker_data *d = xmalloc(sizeof(struct walker_data));
    struct walker *w = xmalloc(sizeof(struct walker));
    memset(w, '\0', sizeof(struct walker));

    /* Create the Interest prefix for fetching individual git objects. The
     * rest of the prefix is appended to the variable in fetch_object. Here we
     * reserve all the memory that will be needed in fetch_object so that it
     * doesn't have to deal with memory checking at runtime. */
    if (!(d->prefix = ccn_charbuf_create())
        || (ccn_charbuf_append(d->prefix, prefix->buf, prefix->length - 1) < 0)
        || (ccn_charbuf_append_tt(d->prefix, CCN_DTAG_Component, CCN_DTAG) < 0)
        || (ccn_charbuf_append_tt(d->prefix, 7, CCN_BLOB) < 0)
        || (ccn_charbuf_append(d->prefix, "objects", 7) < 0)
        || (ccn_charbuf_append_value(d->prefix,
                                     CCN_CLOSE, sizeof(CCN_CLOSE)) < 0)
        || (ccn_charbuf_append_tt(d->prefix, CCN_DTAG_Component, CCN_DTAG) < 0)
        || (ccn_charbuf_append_tt(d->prefix, 40, CCN_BLOB) < 0)
        || (ccn_charbuf_append(d->prefix, EMPTY_TREE_SHA1_HEX, 40) < 0)
        || (ccn_charbuf_append(d->prefix, closer, sizeof(closer)) < 0))
        die("fatal: Out of memory\n");
    d->ccnx = ccnx;

    w->corrupt_object_found = 0;
    w->prefetch = prefetch;
    w->fetch = fetch_object;
    w->cleanup = cleanup;
    w->data = d;

    return w;
}


static void
fetch(struct strbuf *cmd)
{
    const char *ptr;
    char **heads;
    size_t left;
    int res = 0, heads_n = 0;
    struct walker *w = NULL;

    do {
        /* Parse the command line */
        ptr = cmd->buf + FETCH_CMD_LEN + 1;
        left = cmd->len - FETCH_CMD_LEN - 1;
        while(left && isspace(*ptr)) {
            ptr++; left--;
        }
        if (left < 41 || !isspace(ptr[40]))
            goto error;

        /* Add it to the array of all refs */
        heads = xrealloc(heads, sizeof(char *) * ++heads_n);
        heads[heads_n - 1] = xstrndup(ptr, 40);

        /* Parse another line and repeat until empty line */
        strbuf_reset(cmd);
        if (strbuf_getline(cmd, stdin, '\n') == EOF)
            goto error;
        strbuf_trim(cmd);
        if (!cmd->len)
            break;
        if (strncmp(cmd->buf, FETCH_CMD, FETCH_CMD_LEN)
            || !isspace(cmd->buf[FETCH_CMD_LEN]))
            goto error;
    } while(1);

    if (options.depth)
        die("dumb ccnx transport does not support --depth");

    w = get_ccnx_walker(prefix);
    w->get_all = 1;
    w->get_tree = 1;
    w->get_history = 1;
    w->get_verbosely = options.verbosity >= 3;
    w->get_recover = 0;

    if (walker_fetch(w, heads_n, heads, NULL, NULL) < 0)
        goto error;

    printf("\n");
    fflush(stdout);

    goto out;
error:
    res = -1;
out:
    if (w)
        walker_free(w);

    while(heads_n)
        free(heads[--heads_n]);
    free(heads);

    if (res == -1) {
        fprintf(stderr, "fatal: Can't fetch refs.\n");
        exit(128);
    }
}


int
main(int argc, const char **argv)
{
    int nongit, res = EXIT_SUCCESS;
    struct strbuf cmd = STRBUF_INIT;

    /* Setup the internal environment in exec_cmd.c. This initializes the
     * local git directory that we will be modifying. */
    git_extract_argv0_path(argv[0]);
    setup_git_directory_gently(&nongit);
    if (argc < 2) {
        fprintf(stderr, "Remote needed\n");
        goto error;
    }

    options.verbosity = 1;
    options.progress = isatty(2);
    options.thin = 1;

    /* Create a new ccnx handle */
    if (!(ccnx = ccn_create())) {
        fprintf(stderr, "Error while initializing ccnx.\n");
        goto error;
    }
    if (ccn_connect(ccnx, NULL) < 0) {
        fprintf(stderr, "Couldn't connect to local ccnd.\n");
        goto error;
    }

    /* Obtain the prefix for Interest packets from the URL of the remote
     * repository */
    if (!(remote = remote_get(argv[1]))) {
        fprintf(stderr, "Can't figure out which remote to use\n");
        goto error;
    }
    if (!(prefix = ccn_charbuf_create())) {
        fprintf(stderr, "Out of memory\n");
        goto error;
    }
    if (argc > 2)
        url = argv[2];
    else
        url = remote->url[0];
    if (ccn_name_from_uri(prefix, url) < 0) {
        fprintf(stderr, "Invalid prefix '%s'\n", url);
        goto error;
    }

    /* Command processing loop */
    while(1) {
        if (strbuf_getline(&cmd, stdin, '\n') == EOF)
            break;

        strbuf_trim(&cmd);
        if (!cmd.len)
            goto skip;

        if (!strcmp(cmd.buf, "capabilities")) {
            printf("fetch\noption\n\n");
        } else if (!strncmp(cmd.buf, FETCH_CMD, FETCH_CMD_LEN)
                   && isspace(cmd.buf[FETCH_CMD_LEN])) {
            fetch(&cmd);
        } else if (!strncmp(cmd.buf, OPT_CMD, OPT_CMD_LEN)
                   && (isspace(cmd.buf[OPT_CMD_LEN])
                       || !cmd.buf[OPT_CMD_LEN])) {
            option(&cmd);
        } else if (!strncmp(cmd.buf, LIST_CMD, LIST_CMD_LEN)
                   && (isspace(cmd.buf[LIST_CMD_LEN])
                       || !cmd.buf[LIST_CMD_LEN])) {
            list(&cmd);
        } else {
            printf("Unsupported command.\n");
            goto error;
        }

        fflush(stdout);
    skip:
        strbuf_reset(&cmd);
    }

    goto out;
error:
    res = EXIT_FAILURE;
out:
    ccn_charbuf_destroy(&prefix);
    if (ccnx) {
        ccn_disconnect(ccnx);
        ccn_destroy(&ccnx);
    }
    exit(res);
}
