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

#define IS_BLANK(c) ((c) == ' ' || (c) == '\t')

#define OPT_CMD "option"
#define OPT_CMD_LEN (sizeof(OPT_CMD) - 1)

#define LIST_CMD "list"
#define LIST_CMD_LEN (sizeof(LIST_CMD) - 1)

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
            printf("option\n\n");
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
