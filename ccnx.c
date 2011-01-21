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


#define LF "\n"
#define LOC_FMT "[%s:%d] "

#define LOG(fmt, args...) \
    fprintf(stdout, LOC_FMT fmt LF, __FILE__, __LINE__, ## args)
#define DBG(fmt, args...) \
    fprintf(stdout, LOC_FMT "DEBUG: " fmt LF, __FILE__, __LINE__, ## args)
#define ERR(fmt, args...) \
    fprintf(stderr, LOC_FMT "ERROR: " fmt LF, __FILE__, __LINE__, ## args)


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
    -p name  CCNx name prefix to register with ccnd.\n\
    -r dir   Top-level directory with Git repositories.\n\
";


/* This function is CCN Interest handler. It is called whenever ccnd receives
 * a matching Interest packet. The function is supposed to handle the Interest
 * and produce corresponding Data. */
static enum ccn_upcall_res
handle_interest(struct ccn_closure *selfp,
                enum ccn_upcall_kind kind,
                struct ccn_upcall_info *info)
{
    LOG("Interest Request Received");
    return CCN_UPCALL_RESULT_OK;
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


int
main(int argc, char *argv[])
{
    struct ccn *c;
    int res = EXIT_SUCCESS, opt;

    while((opt = getopt(argc, argv, "hp:r:")) != -1) {
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
    if (!(c = setup_ccn_forwarding(prefix, handle_interest)))
        goto error;

    while(1) {
        if (ccn_run(c, -1) < 0) {
            ERR("Error in ccn_run");
            goto error;
        }
    }

    goto out;
error:
    res = EXIT_FAILURE;
out:
    stop_ccn_forwarding(&c);
    ccn_charbuf_destroy(&prefix);
    exit(res);
}
