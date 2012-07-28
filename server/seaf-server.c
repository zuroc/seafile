/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>

#include <glib.h>
#include <glib-object.h>

#include <ccnet.h>
#include <searpc-server.h>
#include <searpc-client.h>
#include <ccnetrpc-transport.h>

#include "seafile-session.h"
#include "seafile-rpc.h"
#include "rpcserver-proc.h"
#include "threaded-rpcserver-proc.h"
#include "log.h"
#include "utils.h"

#include "processors/check-tx-slave-proc.h"
#include "processors/check-tx-slave-v2-proc.h"
#include "processors/putcommit-proc.h"
#include "processors/recvcommit-proc.h"
#include "processors/recvfs-proc.h"
#include "processors/putfs-proc.h"
#include "processors/putblock-proc.h"
#include "processors/putblock-v2-proc.h"
#include "processors/recvblock-proc.h"
#include "processors/recvblock-v2-proc.h"
#include "processors/recvbranch-proc.h"
#include "processors/sync-repo-slave-proc.h"
#include "processors/putcommit-v2-proc.h"
#include "processors/recvcommit-v2-proc.h"
#include "processors/recvcommit-v3-proc.h"
#include "processors/putrepoemailtoken-proc.h"

SeafileSession *seaf;
SearpcClient *ccnetrpc_client;
SearpcClient *ccnetrpc_client_t;
SearpcClient *async_ccnetrpc_client;
SearpcClient *async_ccnetrpc_client_t;

static const char *short_options = "hvc:d:l:fg:G:m";
static struct option long_options[] = {
    { "help", no_argument, NULL, 'h', },
    { "version", no_argument, NULL, 'v', },
    { "config-file", required_argument, NULL, 'c' },
    { "seafdir", required_argument, NULL, 'd' },
    { "log", required_argument, NULL, 'l' },
    { "foreground", no_argument, NULL, 'f' },
    { "ccnet-debug-level", required_argument, NULL, 'g' },
    { "seafile-debug-level", required_argument, NULL, 'G' },
    { "master", no_argument, NULL, 'm'},
    { NULL, 0, NULL, 0, },
};

static void usage ()
{
    fprintf (stderr, "usage: seaf-server [-c config_dir] [-d seafile_dir]\n");
}

static void register_processors (CcnetClient *client)
{
    ccnet_register_service (client, "seafile-check-tx-slave", "basic",
                            SEAFILE_TYPE_CHECK_TX_SLAVE_PROC, NULL);
    ccnet_register_service (client, "seafile-check-tx-slave-v2", "basic",
                            SEAFILE_TYPE_CHECK_TX_SLAVE_V2_PROC, NULL);
    ccnet_register_service (client, "seafile-putcommit", "basic",
                            SEAFILE_TYPE_PUTCOMMIT_PROC, NULL);
    ccnet_register_service (client, "seafile-recvcommit", "basic",
                            SEAFILE_TYPE_RECVCOMMIT_PROC, NULL);
    ccnet_register_service (client, "seafile-putblock", "basic",
                            SEAFILE_TYPE_PUTBLOCK_PROC, NULL);
    ccnet_register_service (client, "seafile-putblock-v2", "basic",
                            SEAFILE_TYPE_PUTBLOCK_V2_PROC, NULL);
    ccnet_register_service (client, "seafile-recvblock", "basic",
                            SEAFILE_TYPE_RECVBLOCK_PROC, NULL);
    ccnet_register_service (client, "seafile-recvblock-v2", "basic",
                            SEAFILE_TYPE_RECVBLOCK_V2_PROC, NULL);
    ccnet_register_service (client, "seafile-recvfs", "basic",
                            SEAFILE_TYPE_RECVFS_PROC, NULL);
    ccnet_register_service (client, "seafile-putfs", "basic",
                            SEAFILE_TYPE_PUTFS_PROC, NULL);
    ccnet_register_service (client, "seafile-recvbranch", "basic",
                            SEAFILE_TYPE_RECVBRANCH_PROC, NULL);
    ccnet_register_service (client, "seafile-sync-repo-slave", "basic",
                            SEAFILE_TYPE_SYNC_REPO_SLAVE_PROC, NULL);
    ccnet_register_service (client, "seafile-putcommit-v2", "basic",
                            SEAFILE_TYPE_PUTCOMMIT_V2_PROC, NULL);
    ccnet_register_service (client, "seafile-recvcommit-v2", "basic",
                            SEAFILE_TYPE_RECVCOMMIT_V2_PROC, NULL);
    ccnet_register_service (client, "seafile-recvcommit-v3", "basic",
                            SEAFILE_TYPE_RECVCOMMIT_V3_PROC, NULL);
    ccnet_register_service (client, "seafile-put-repo-email-token", "basic",
                            SEAFILE_TYPE_PUTREPOEMAILTOKEN_PROC, NULL);
}

#include <searpc.h>
#include "searpc-signature.h"
#include "searpc-marshal.h"

static void start_rpc_service (CcnetClient *client)
{
    searpc_server_init (register_marshals);

    searpc_create_service ("seafserv-rpcserver");
    ccnet_register_service (client, "seafserv-rpcserver", "rpc-inner",
                            CCNET_TYPE_RPCSERVER_PROC, NULL);

    searpc_create_service ("seafserv-threaded-rpcserver");
    ccnet_register_service (client, "seafserv-threaded-rpcserver", "rpc-inner",
                            CCNET_TYPE_THREADED_RPCSERVER_PROC, NULL);

    /* threaded services */

    /* repo manipulation */
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_repo,
                                     "seafile_get_repo",
                                     searpc_signature_object__string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_destroy_repo,
                                     "seafile_destroy_repo",
                                     searpc_signature_int__string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_repo_list,
                                     "seafile_get_repo_list",
                                     searpc_signature_objlist__int_int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_org_repo_list,
                                     "seafile_get_org_repo_list",
                                     searpc_signature_objlist__int_int_int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_remove_org_repo_by_org_id,
                                     "seafile_remove_org_repo_by_org_id",
                                     searpc_signature_int__int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_repo_owner,
                                     "seafile_get_repo_owner",
                                     searpc_signature_string__string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_is_repo_owner,
                                     "seafile_is_repo_owner",
                                     searpc_signature_int__string_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_list_owned_repos,
                                     "seafile_list_owned_repos",
                                     searpc_signature_objlist__string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_server_repo_size,
                                     "seafile_server_repo_size",
                                     searpc_signature_int64__string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_repo_set_access_property,
                                     "seafile_repo_set_access_property",
                                     searpc_signature_int__string_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_repo_query_access_property,
                                     "seafile_repo_query_access_property",
                                     searpc_signature_string__string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_revert_on_server,
                                     "seafile_revert_on_server",
                                     searpc_signature_int__string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_diff,
                                     "seafile_diff",
                                     searpc_signature_objlist__string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_post_file,
                                     "seafile_post_file",
                    searpc_signature_int__string_string_string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_put_file,
                                     "seafile_put_file",
                    searpc_signature_int__string_string_string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_post_dir,
                                     "seafile_post_dir",
                        searpc_signature_int__string_string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_del_file,
                                     "seafile_del_file",
                        searpc_signature_int__string_string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_copy_file,
                                     "seafile_copy_file",
       searpc_signature_int__string_string_string_string_string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_move_file,
                                     "seafile_move_file",
       searpc_signature_int__string_string_string_string_string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_rename_file,
                                     "seafile_rename_file",
                    searpc_signature_int__string_string_string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_is_valid_filename,
                                     "seafile_is_valid_filename",
                                     searpc_signature_int__string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_create_repo,
                                     "seafile_create_repo",
                                     searpc_signature_string__string_string_string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_commit,
                                     "seafile_get_commit",
                                     searpc_signature_object__string());
    
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_list_dir,
                                     "seafile_list_dir",
                                     searpc_signature_objlist__string());
    
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_file_size,
                                     "seafile_get_file_size",
                                     searpc_signature_int64__string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_list_dir_by_path,
                                     "seafile_list_dir_by_path",
                                     searpc_signature_objlist__string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_file_by_path,
                                     "seafile_get_file_by_path",
                                     searpc_signature_string__string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_list_file_revisions,
                                     "seafile_list_file_revisions",
                                     searpc_signature_objlist__string_string());

    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_revert_file,
                                     "seafile_revert_file",
                                     searpc_signature_int__string_string_string_string());

    /* share repo to user */
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_add_share,
                                     "seafile_add_share",
                                     searpc_signature_int__string_string_string_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_list_share_repos,
                                     "seafile_list_share_repos",
                                     searpc_signature_objlist__string_string_int_int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_remove_share,
                                     "seafile_remove_share",
                                     searpc_signature_int__string_string_string());

    /* share repo to group */
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_group_share_repo,
                                     "seafile_group_share_repo",
                                     searpc_signature_int__string_int_string_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_group_unshare_repo,
                                     "seafile_group_unshare_repo",
                                     searpc_signature_int__string_int_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_group_repoids,
                                     "seafile_get_group_repoids",
                                     searpc_signature_string__int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_group_my_share_repos,
                                     "seafile_get_group_my_share_repos",
                                     searpc_signature_objlist__string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_group_repo_share_from,
                                     "seafile_get_group_repo_share_from",
                                     searpc_signature_string__string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_remove_repo_group,
                                     "seafile_remove_repo_group",
                                     searpc_signature_int__int_string());    
    
    /* branch and commit */
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_branch_gets,
                                     "seafile_branch_gets",
                                     searpc_signature_objlist__string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_commit_list,
                                     "seafile_get_commit_list",
                                     searpc_signature_objlist__string_int_int());

    /* token */
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_set_repo_token,
                                     "seafile_set_repo_token",
                                     searpc_signature_int__string_string_string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_repo_token_nonnull,
                                     "seafile_get_repo_token_nonnull",
                                     searpc_signature_string__string_string());

    /* quote */
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_user_quota_usage,
                                     "seafile_get_user_quota_usage",
                                     searpc_signature_int64__string());


    /* -------- rpc services -------- */
    /* token for web access to repo */
    searpc_server_register_function ("seafserv-rpcserver",
                                     seafile_web_save_access_token,
                                     "seafile_web_save_access_token",
                                     searpc_signature_int__string_string_string_string_string());
    searpc_server_register_function ("seafserv-rpcserver",
                                     seafile_web_query_access_token,
                                     "seafile_web_query_access_token",
                                     searpc_signature_object__string());

    /* chunk server manipulation */
    searpc_server_register_function ("seafserv-rpcserver",
                                     seafile_add_chunk_server,
                                     "seafile_add_chunk_server",
                                     searpc_signature_int__string());
    searpc_server_register_function ("seafserv-rpcserver",
                                     seafile_del_chunk_server,
                                     "seafile_del_chunk_server",
                                     searpc_signature_int__string());
    searpc_server_register_function ("seafserv-rpcserver",
                                     seafile_list_chunk_servers,
                                     "seafile_list_chunk_servers",
                                     searpc_signature_string__void());

    /* set monitor */
    searpc_server_register_function ("seafserv-rpcserver",
                                     seafile_set_monitor,
                                     "seafile_set_monitor",
                                     searpc_signature_int__string());
    searpc_server_register_function ("seafserv-rpcserver",
                                     seafile_get_monitor,
                                     "seafile_get_monitor",
                                     searpc_signature_string__void());

    /* gc */
    searpc_server_register_function ("seafserv-rpcserver",
                                     seafile_gc,
                                     "seafile_gc",
                                     searpc_signature_int__void());
    searpc_server_register_function ("seafserv-rpcserver",
                                     seafile_gc_get_progress,
                                     "seafile_gc_get_progress",
                                     searpc_signature_int__void());

    /* password management */
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_set_passwd,
                                     "seafile_set_passwd",
                                     searpc_signature_int__string_string_string());
    searpc_server_register_function ("seafserv-rpcserver",
                                     seafile_is_passwd_set,
                                     "seafile_is_passwd_set",
                                     searpc_signature_int__string_string());
    searpc_server_register_function ("seafserv-rpcserver",
                                     seafile_get_decrypt_key,
                                     "seafile_get_decrypt_key",
                                     searpc_signature_object__string_string());

    /* quota management */
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_set_user_quota,
                                     "set_user_quota",
                                     searpc_signature_int__string_int64());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_user_quota,
                                     "get_user_quota",
                                     searpc_signature_int64__string());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_set_org_quota,
                                     "set_org_quota",
                                     searpc_signature_int__int_int64());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_org_quota,
                                     "get_org_quota",
                                     searpc_signature_int64__int());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_set_org_user_quota,
                                     "set_org_user_quota",
                                     searpc_signature_int__int_string_int64());
    searpc_server_register_function ("seafserv-threaded-rpcserver",
                                     seafile_get_org_user_quota,
                                     "get_org_user_quota",
                                     searpc_signature_int64__int_string());
}

static void
set_signal_handlers (SeafileSession *session)
{
#ifndef WIN32
    signal (SIGPIPE, SIG_IGN);
#endif
}

static void
create_sync_rpc_clients (const char *config_dir)
{
    CcnetClient *sync_client;

    /* sync client and rpc client */
    sync_client = ccnet_client_new ();
    if ( (ccnet_client_load_confdir(sync_client, config_dir)) < 0 ) {
        fprintf (stderr, "Read config dir error\n");
        exit(1);
    }

    if (ccnet_client_connect_daemon (sync_client, CCNET_CLIENT_SYNC) < 0)
    {
        fprintf(stderr, "Connect to server fail: %s\n", strerror(errno));
        exit(1);
    }

    ccnetrpc_client = ccnet_create_rpc_client (sync_client, NULL, "ccnet-rpcserver");
    ccnetrpc_client_t = ccnet_create_rpc_client (sync_client,
                                                 NULL,
                                                 "ccnet-threaded-rpcserver");
}

static void
create_async_rpc_clients (CcnetClient *client)
{
    async_ccnetrpc_client = ccnet_create_async_rpc_client (
        client, NULL, "ccnet-rpcserver");
    async_ccnetrpc_client_t = ccnet_create_async_rpc_client (
        client, NULL, "ccnet-threaded-rpcserver");
}

int
main (int argc, char **argv)
{
    int c;
    char *config_dir = DEFAULT_CONFIG_DIR;
    char *seafile_dir = NULL;
    char *logfile = NULL;
    int daemon_mode = 1;
    int is_master = 0;
    CcnetClient *client;
    char *ccnet_debug_level_str = "info";
    char *seafile_debug_level_str = "debug";

    while ((c = getopt_long (argc, argv, short_options, 
                             long_options, NULL)) != EOF)
    {
        switch (c) {
        case 'h':
            exit (1);
            break;
        case 'v':
            exit (1);
            break;
        case 'c':
            config_dir = optarg;
            break;
        case 'd':
            seafile_dir = g_strdup(optarg);
            break;
        case 'f':
            daemon_mode = 0;
            break;
        case 'l':
            logfile = g_strdup(optarg);
            break;
        case 'g':
            ccnet_debug_level_str = optarg;
            break;
        case 'G':
            seafile_debug_level_str = optarg;
            break;
        case 'm':
            is_master = 1;
        default:
            usage ();
            exit (1);
        }
    }

    argc -= optind;
    argv += optind;

#ifndef WIN32
    if (daemon_mode)
        daemon (1, 0);
#endif

    g_type_init ();
#if !GLIB_CHECK_VERSION(2,32,0)
    g_thread_init (NULL);
#endif
    client = ccnet_init (config_dir);
    if (!client)
        exit (1);

    register_processors (client);

    start_rpc_service (client);

    create_sync_rpc_clients (config_dir);
    create_async_rpc_clients (client);

    if (seafile_dir == NULL)
        seafile_dir = g_build_filename (config_dir, "seafile", NULL);
    if (logfile == NULL)
        logfile = g_build_filename (seafile_dir, "seafile.log", NULL);

    seaf = seafile_session_new (seafile_dir, client);
    if (!seaf) {
        fprintf (stderr, "Failed to create seafile session.\n");
        exit (1);
    }
    seaf->is_master = is_master;
    seaf->ccnetrpc_client = ccnetrpc_client;
    seaf->async_ccnetrpc_client = async_ccnetrpc_client;
    seaf->ccnetrpc_client_t = ccnetrpc_client_t;
    seaf->async_ccnetrpc_client_t = async_ccnetrpc_client_t;

    if (seafile_log_init (logfile, ccnet_debug_level_str,
                          seafile_debug_level_str) < 0) {
        fprintf (stderr, "Failed to init log.\n");
        exit (1);
    }

    g_free (seafile_dir);
    g_free (logfile);

    set_signal_handlers (seaf);

    /* init seaf */
    seafile_session_init (seaf);

    seafile_session_start (seaf);

    ccnet_main (client);

    return 0;
}