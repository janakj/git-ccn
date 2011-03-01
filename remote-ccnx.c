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

#define IS_BLANK(c) ((c) == ' ' || (c) == '\t')

/* CCNx library handle */
static struct ccn *ccnx;

/* The handle for the remote repositor */
static struct remote *remote;

/* The URL of the remote repository */
static const char *url;
/* CCNx prefix created from the URL */
static struct ccn_charbuf *prefix;


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
            printf("\n");
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
