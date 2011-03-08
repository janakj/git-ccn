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


/* This function is CCN Interest handler. It is called whenever ccnd receives
 * a matching Interest packet. The function is supposed to handle the Interest
 * and produce corresponding Data. */
static enum ccn_upcall_res
handle_interest(struct ccn_closure *selfp,
                enum ccn_upcall_kind kind,
                struct ccn_upcall_info *info)
{
    INF("Interest Request Received");
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
    stop_logger();
    exit(res);
}
