#include "common.h"

#define DEBUG_FLAG SEAFILE_DEBUG_TRANSFER
#include "log.h"

#include <unistd.h>
#include <limits.h>
#include <string.h>

#include "file-upload-mgr.h"
#include <ccnet.h>
#include "utils.h"

#include "seafile-session.h"
#include "commit-mgr.h"
#include "fs-mgr.h"
#include "block-mgr.h"
#include "bitfield.h"
#include "seafile-error.h"
#include "vc-common.h"
#include "merge.h"
#include "sync-mgr.h"
#include "vc-utils.h"
#include "gc.h"
#include "mq-mgr.h"

#include "processors/check-file-upload-proc.h"
#include "processors/uploadfs-proc.h"
#include "processors/uploadblock-proc.h"
#include "processors/getcs-v2-proc.h"
#include "processors/commit-upload-file-proc.h"
#include "processors/uploadcommit-proc.h"

#define FILE_UPLOAD_DB "fileupload.db"

#define SCHEDULE_INTERVAL   1 /* 1s */
#define MAX_QUEUED_BLOCKS   50

static const char *upload_task_state_strs[] = {
    "normal",
    "cancelled",
    "finished",
    "error",
};

static const char *upload_task_rt_state_strs[] = {
    "init",
    "check",
    "import",
    "fs",
    "data",
    "commit",
    "update branch",
    "finished",
    "netdown",
};

static const char *upload_task_error_strs[] = {
    "Successful",
    "Unknown Error",
    "Service on remote server is not avaialbe",
    "Access denied to service. Please check your registration on server",
    "Interval error when preparing upload",
    "No permission to access remote library",
    "Import local file failure",
    "Internal error when starting to send revision information",
    "Failed to upload revision information to remote library",
    "Internal error when starting to send file information",
    "Incomplete file information in the local library",
    "Incomplete block information in the local library",
    "Internal error when starting to update remote library",
};

static const char *upload_task_state_to_str(int state)
{
    return upload_task_state_strs[state];
}

static const char *upload_task_rt_state_to_str(int rt_state)
{
    return upload_task_rt_state_strs[rt_state];
}

static const char *upload_task_error_str(int task_errno)
{
    return upload_task_error_strs[task_errno];
}

static UploadTask *seaf_upload_task_new (SeafFileUploadManager *mgr,
                                         const char *tx_id,
                                         const char *dest_id,
                                         const char *filepath,
                                         const char *repoid,
                                         const char *topath);
static gboolean get_undone_tasks (sqlite3_stmt *stmt, void *data);
static int remove_task_state(UploadTask *task);
static int schedule_task_pulse (void *vmanager);
static int start_upload_file(UploadTask *task);
static void cancel_task (UploadTask *task);
static void clean_task_for_repo (SeafFileUploadManager *mgr,
                                 const char *repoid);
static void emit_upload_done_signal(UploadTask *task);
static void free_task_resources (UploadTask *task);
static void import_job_done(void *data);
static void register_processors(CcnetClient *client);
static void schedule_upload_task(UploadTask *task);
static void seaf_upload_task_free(UploadTask *task);
static void start_import_file(UploadTask *task);
static void state_machine_tick (UploadTask *task);
static void transition_state (UploadTask *task, int state, int rt_state);
static void transition_state_on_error(UploadTask *task, int task_errno);
static void upload_task_with_proc_failure(UploadTask *task,
                                          CcnetProcessor *proc,
                                          int default_error);

SeafFileUploadManager *
seaf_file_upload_manager_new (SeafileSession *seaf)
{
    SeafFileUploadManager *mgr = g_new0 (SeafFileUploadManager, 1);
    char *db_path;

    mgr->seaf = seaf;
    mgr->upload_tasks = g_hash_table_new_full(g_str_hash, g_str_equal,
                                              (GDestroyNotify)g_free,
                                              (GDestroyNotify)seaf_upload_task_free);

    db_path = g_build_path (PATH_SEPERATOR, seaf->seaf_dir,
                            FILE_UPLOAD_DB, NULL);
    if (sqlite_open_db (db_path, &mgr->db) < 0) {
        g_critical ("[File upload mgr] Failed to open file upload db\n");
        g_free (db_path);
        g_free (mgr);
        return NULL;
    }

    return mgr;
}

int
seaf_file_upload_manager_init (SeafFileUploadManager *mgr)
{
    const char *sql = "CREATE TABLE IF NOT EXISTS UploadFiles "
                      "(repo_id TEXT PRIMARY KEY, filepath TEXT,"
                      " topath TEXT, status INTEGER);";
    if (sqlite_query_exec (mgr->db, sql) < 0)
        return -1;

    sql = "SELECT * FROM UploadFiles";
    if (sqlite_foreach_selected_row (mgr->db, sql, get_undone_tasks, mgr))
        return -1;

    return 0;
}

int
seaf_file_upload_manager_start (SeafFileUploadManager *mgr)
{
    register_processors(seaf->session);

    mgr->schedule_timer = ccnet_timer_new (schedule_task_pulse, mgr,
                                           SCHEDULE_INTERVAL * 1000);

    return 0;
}

static void register_processors(CcnetClient *client)
{
    ccnet_proc_factory_register_processor(client->proc_factory,
                                          "seafile-check-file-upload",
                                          SEAFILE_TYPE_CHECK_FILE_UPLOAD_PROC);
    ccnet_proc_factory_register_processor(client->proc_factory,
                                          "seafile-uploadfs",
                                          SEAFILE_TYPE_UPLOADFS_PROC);
    ccnet_proc_factory_register_processor(client->proc_factory,
                                          "seafile-uploadblock",
                                          SEAFILE_TYPE_UPLOAD_BLOCK_PROC);
    ccnet_proc_factory_register_processor (client->proc_factory,
                                           "seafile-getcs-v2",
                                           SEAFILE_TYPE_GETCS_V2_PROC);
    ccnet_proc_factory_register_processor (client->proc_factory,
                                           "seafile-commit-upload-file",
                                           SEAFILE_TYPE_COMMIT_UPLOAD_FILE_PROC);
    ccnet_proc_factory_register_processor (client->proc_factory,
                                           "seafile-upload-commit",
                                           SEAFILE_TYPE_UPLOAD_COMMIT_PROC);
}

int
seaf_file_upload_manager_add_task (SeafFileUploadManager *mgr,
                                   const char *filepath,
                                   const char *peerid,
                                   const char *repoid,
                                   const char *topath,
                                   GError **error)
{
    UploadTask *task;

    clean_task_for_repo (mgr, repoid);

    task = seaf_upload_task_new (mgr, NULL, peerid, filepath, repoid, topath);
    if (!task) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, "Out of memory");
        return -1;
    }

    task->state = UPLOAD_TASK_STATE_NORMAL;
    g_hash_table_insert (mgr->upload_tasks, g_strdup(task->tx_id), task);

    return 0;
}

static gboolean
get_undone_tasks (sqlite3_stmt *stmt, void *data)
{
    /* TODO: load undone upload tasks from db */
    return TRUE;
}

static int
schedule_task_pulse (void *vmanager)
{
    SeafFileUploadManager *mgr = (SeafFileUploadManager *)vmanager;
    GHashTableIter iter;
    gpointer key, value;
    UploadTask *task;
    
    /* get upload task list in transfering, and send msg to upper layer */

    g_hash_table_iter_init(&iter, mgr->upload_tasks);
    while (g_hash_table_iter_next(&iter, &key, &value)) {
        task = (UploadTask *)value;
        state_machine_tick(task);
    }

    return 1;
}

static void state_machine_tick (UploadTask *task)
{
    switch (task->state) {
    case UPLOAD_TASK_STATE_NORMAL:
        if (!seaf_repo_manager_repo_exists(seaf->repo_mgr, task->repo_id)) {
            cancel_task(task);
            break;
        }

        if (task->runtime_state == UPLOAD_TASK_RT_NETDOWN) {
            if (task->dest_id &&
                ccnet_peer_is_ready(seaf->ccnetrpc_client, task->dest_id)) {
                seaf_debug("[file-up-mgr] Resume transfer repo %.8s when "
                           "peer %.10s is reconnected\n",
                           task->repo_id, task->dest_id);
            }
        } else if (task->runtime_state != UPLOAD_TASK_RT_FINISHED) {
            schedule_upload_task(task);
        } else {
            /* normal && finish, can't happen */
            g_assert(0);
        }
        break;
    case UPLOAD_TASK_STATE_FINISHED:
        g_assert(task->runtime_state == UPLOAD_TASK_RT_FINISHED);
        break;
    case UPLOAD_TASK_STATE_CANCELED:
        if (task->runtime_state == UPLOAD_TASK_RT_DATA) {
            free_task_resources(task);
            transition_state(task, UPLOAD_TASK_STATE_CANCELED,
                             UPLOAD_TASK_RT_FINISHED);
        }
        break;
    case UPLOAD_TASK_STATE_ERROR:
        g_assert(task->runtime_state == UPLOAD_TASK_RT_FINISHED);
        break;
    default:
        seaf_warning("state %d\n", task->state);
        g_assert(0);
    }
}

static int
start_getcs_proc (UploadTask *task, const char *peer_id)
{
    CcnetProcessor *processor;

    processor = ccnet_proc_factory_create_remote_master_processor (
        seaf->session->proc_factory, "seafile-getcs-v2", peer_id);
    if (!processor) {
        seaf_warning ("failed to create get chunk server proc.\n");
        return -1;
    }
    ((SeafileGetcsV2Proc *)processor)->task = task;

    if (ccnet_processor_startl (processor, NULL) < 0) {
        seaf_warning ("failed to start get chunk server proc.\n");
        return -1;
    }

    return 0;
}

static int
get_chunk_server_list (UploadTask *task)
{
    const char *dest_id = task->dest_id;

    if (!dest_id)
        return -1;

    if (!ccnet_peer_is_ready (seaf->ccnetrpc_client, dest_id))
        return -1;

    if (start_getcs_proc (task, dest_id) < 0)
        return -1;

    return 0;
}

static void
upload_block_done_cb(CcnetProcessor *processor, gboolean success, void *data)
{
    UploadTask *task = (UploadTask *)data;

    if (!success && task->state == UPLOAD_TASK_STATE_ERROR) {
        free_task_resources(task);
    } else {
        g_hash_table_remove(task->processors, processor->peer_id);
    }
}

static CcnetProcessor *
start_upload_block_proc(UploadTask *task, const char *peer_id)
{
    CcnetProcessor *processor = NULL;

    if (!ccnet_peer_is_ready(seaf->ccnetrpc_client, peer_id))
        return NULL;

    processor = ccnet_proc_factory_create_remote_master_processor(
            seaf->session->proc_factory, "seafile-uploadblock", peer_id);
    if (!processor) {
        seaf_warning("failed to create uploadblock proc.\n");
        return NULL;
    }

    ((SeafileUploadBlockProc *)processor)->task = task;
    if (ccnet_processor_start(processor, 0, NULL) < 0) {
        seaf_warning("failed to start uploadblock proc.\n");
        return NULL;
    }

    g_signal_connect(processor, "done", (GCallback)upload_block_done_cb, task);

    return processor;
}

static void
start_chunk_server_upload(UploadTask *task)
{
    GList *ptr = task->chunk_servers;
    const char *cs_id;
    CcnetProcessor *processor;

    while (ptr) {
        cs_id = ptr->data;
        if (!g_hash_table_lookup(task->processors, cs_id)) {
            processor = start_upload_block_proc(task, cs_id);
            if (processor != NULL) {
                g_hash_table_insert(task->processors, g_strdup(cs_id), processor);
            }
        }
        ptr = ptr->next;
    }
}

static void
upload_dispatch_blocks_to_processor (UploadTask *task,
                                     SeafileUploadBlockProc *proc,
                                     guint n_procs)
{
    CcnetProcessor *processor = (CcnetProcessor *)proc;
    int expected, n_blocks, n_scheduled = 0;
    int i;

    if (!seafile_upload_block_proc_is_ready (proc))
        return;

    expected = MIN (task->uploaded.bitCount/n_procs, MAX_QUEUED_BLOCKS);
    n_blocks = expected - proc->pending_blocks;
    if (n_blocks <= 0)
        return;

    seaf_debug ("expected: %d, pending: %d.\n", expected, proc->pending_blocks);

    for (i = 0; i < task->uploaded.bitCount; ++i) {
        if (n_scheduled == n_blocks)
            break;

        if (!BitfieldHasFast (&task->uploaded, i) &&
            BitfieldHasFast (&task->block_list->block_map, i) &&
            !BitfieldHasFast (&task->active, i))
        {
            const char *block_id;
            block_id = g_ptr_array_index (task->block_list->block_ids, i);
            seaf_debug ("Transfer repo %.8s: schedule block %.8s to %.8s.\n",
                     task->repo_id, block_id, processor->peer_id);
            seafile_upload_block_proc_send_block (proc, i);
            BitfieldAdd (&task->active, i);
            ++n_scheduled;
        }
    }
}

static void
upload_dispatch_blocks (UploadTask *task)
{
    GHashTableIter iter;
    gpointer key, value;
    SeafileUploadBlockProc *proc;
    guint n_procs = g_hash_table_size (task->processors);

    g_hash_table_iter_init (&iter, task->processors);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        proc = value;
        upload_dispatch_blocks_to_processor (task, proc, n_procs);
    }
}

static gboolean
collect_block_processor (gpointer key, gpointer value, gpointer data)
{
    CcnetProcessor *processor = value;
    GList **pproc_list = data;

    *pproc_list = g_list_prepend (*pproc_list, processor);

    return TRUE;
}

static void
free_task_resources (UploadTask *task)
{
    GList *proc_list = NULL;
    GList *ptr;

    /* We must first move processors from the hash table into
     * a list, because tx_done_cb() tries to remove the proc
     * from the hash table too. We can't remove an element
     * from the hash table while traversing it.
     */
    g_hash_table_foreach_remove (task->processors,
                                 collect_block_processor,
                                 &proc_list);
    ptr = proc_list;
    while (ptr != NULL) {
        CcnetProcessor *processor = ptr->data;
        ccnet_processor_done (processor, TRUE);
        ptr = g_list_delete_link (ptr, ptr);
    }

    block_list_free (task->block_list);
    task->block_list = NULL;
    BitfieldDestruct (&task->active);

    for (ptr = task->chunk_servers; ptr; ptr = ptr->next) 
        g_free (ptr->data);
    g_list_free (task->chunk_servers);
    task->chunk_servers = NULL;

    BitfieldDestruct (&task->uploaded);
}

static void
update_branch_cb (CcnetProcessor *processor, gboolean success, void *data)
{
    UploadTask *task = data;

    if (success) {
        transition_state (task, UPLOAD_TASK_STATE_FINISHED, UPLOAD_TASK_RT_FINISHED);

        SeafRepo *repo;
        repo = seaf_repo_manager_get_repo(seaf->repo_mgr, task->repo_id);

        SeafBranch *branch;
        branch = seaf_branch_manager_get_branch (seaf->branch_mgr,
                                                 task->repo_id,
                                                 repo->head->name);
        if (!branch) {
            branch = seaf_branch_new ("master", task->repo_id, task->new_commit->commit_id);
            seaf_branch_manager_add_branch (seaf->branch_mgr, branch);
            seaf_branch_unref (branch);
        } else {
            seaf_branch_set_commit (branch, task->new_commit->commit_id);
            seaf_branch_manager_update_branch (seaf->branch_mgr, branch);
            seaf_branch_unref (branch);
        }

#if 0
        /* Save remote head for GC (used when repo doesn't keep local history) */
        seaf_repo_manager_set_repo_property (seaf->repo_mgr, task->repo_id,
                                             REPO_REMOTE_HEAD, task->head);
#endif
    } else if (task->state != UPLOAD_TASK_STATE_ERROR
               && task->runtime_state == UPLOAD_TASK_RT_UPDATE_BRANCH) {
        upload_task_with_proc_failure (
            task, processor, UPLOAD_TASK_ERR_UNKNOWN);
    }
    /* Errors have been processed in the processor. */
}

static int
update_remote_branch(UploadTask *task)
{
    CcnetProcessor *processor;

    processor = ccnet_proc_factory_create_remote_master_processor (
        seaf->session->proc_factory, "seafile-commit-upload-file", task->dest_id);
    if (!processor) {
        seaf_warning ("failed to create sendbranch proc.\n");
        goto fail;
    }

    g_signal_connect (processor, "done", (GCallback)update_branch_cb, task);

    ((SeafileCommitUploadFileProc *)processor)->task = task;
    if (ccnet_processor_startl (processor, task->repo_id, task->fs_sha1,
                                task->topath, NULL) < 0)
    {
        seaf_warning ("failed to start sendbranch proc.\n");
        goto fail;
    }

    transition_state (task, task->state, UPLOAD_TASK_RT_UPDATE_BRANCH);
    return 0;

fail:
    transition_state_on_error (task, UPLOAD_TASK_ERR_START_UPDATE_BRANCH);
    return -1;
}

static void schedule_upload_task(UploadTask *task)
{
    switch (task->runtime_state) {
    case UPLOAD_TASK_RT_INIT:
        start_import_file(task);
        break;
    case UPLOAD_TASK_RT_IMPORT:
        start_upload_file(task);
        break;
    case UPLOAD_TASK_RT_DATA:
        if (task->n_uploaded == task->block_list->n_blocks) {
            free_task_resources (task);
            update_remote_branch (task);
            transition_state(task, UPLOAD_TASK_STATE_FINISHED,
                             UPLOAD_TASK_RT_FINISHED);
            break;
        }

        if (task->chunk_servers == NULL)
            get_chunk_server_list(task);
        start_chunk_server_upload(task);
        upload_dispatch_blocks(task);
        break;
    default:
        break;
    }
}

void
upload_task_set_netdown (UploadTask *task)
{
    g_assert (task->state == UPLOAD_TASK_STATE_NORMAL);
    if (task->runtime_state == UPLOAD_TASK_RT_NETDOWN)
        return;
    transition_state (task, UPLOAD_TASK_STATE_NORMAL, UPLOAD_TASK_RT_NETDOWN);
}

static void upload_task_with_proc_failure(UploadTask *task,
                                          CcnetProcessor *proc,
                                          int default_error)
{
    seaf_debug ("Upload file repo '%.8s': proc %s(%d) failure: %d\n",
                task->repo_id,
                GET_PNAME(proc), PRINT_ID(proc->id),
                proc->failure);

    switch (proc->failure) {
    case PROC_DONE:
        /* It can never happen */
        g_assert(0);
    case PROC_REMOTE_DEAD:
        seaf_warning ("[file-upload-mgr] Shutdown processor with failure %d\n",
                   proc->failure);
        upload_task_set_netdown (task);
        break;
    case PROC_NO_SERVICE:
        transition_state_on_error (task, UPLOAD_TASK_ERR_NO_SERVICE);
        break;
    case PROC_PERM_ERR:
        transition_state_on_error (task, UPLOAD_TASK_ERR_PROC_PERM_ERR);
        break;
    case PROC_BAD_RESP:
    case PROC_NOTSET:
    default:
        transition_state_on_error (task, default_error);
    }
}

static BlockList *
load_block_list(UploadTask *task)
{
    BlockList *bl = NULL;
    Seafile *seafile;
    int i;

    bl = block_list_new();

    seafile = seaf_fs_manager_get_seafile (seaf->fs_mgr, task->fs_sha1);
    if (!seafile) {
        g_warning ("[file-upload-mgr] Failed to find file %s.\n", task->fs_sha1);
        return FALSE;
    }

    for (i = 0; i < seafile->n_blocks; ++i)
        block_list_insert (bl, seafile->blk_sha1s[i]);

    seafile_unref (seafile);

    return bl;
}

static int
seaf_upload_task_load_blocklist(UploadTask *task)
{
    BlockList *bl = NULL;

    bl = load_block_list(task);
    if (!bl) {
        seaf_warning("Failed to populate block list.\n");
        return -1;
    }

    block_list_generate_bitmap(bl);

    task->block_list = bl;
    BitfieldConstruct(&task->active, bl->n_blocks);
    BitfieldConstruct(&task->uploaded, bl->n_blocks);

    return 0;
}

static void
start_block_upload(UploadTask *task)
{
    if (seaf_upload_task_load_blocklist(task) < 0) {
        transition_state_on_error(task, UPLOAD_TASK_ERR_LOAD_BLOCK_LIST);
    } else {
        transition_state(task, task->state, UPLOAD_TASK_RT_DATA);
    }
    state_machine_tick(task);
}

static void
on_fs_uploaded(CcnetProcessor *processor, gboolean success, void *data)
{
    UploadTask *task = (UploadTask *)data;

    if (task->state == UPLOAD_TASK_STATE_CANCELED) {
        transition_state(task, task->state, UPLOAD_TASK_RT_FINISHED);
        goto out;
    }

    if (success) {
        start_block_upload(task);
    } else if (task->state != UPLOAD_TASK_STATE_ERROR
               && task->runtime_state == UPLOAD_TASK_RT_FS) {
        upload_task_with_proc_failure(
                task, processor, UPLOAD_TASK_ERR_UPLOAD_FS);
    }

out:
    g_signal_handlers_disconnect_by_func(processor, on_fs_uploaded, data);
}

static int
start_uploadfs_proc(UploadTask *task, const char *peer_id, GCallback done_cb)
{
    CcnetProcessor *processor;

    processor = ccnet_proc_factory_create_remote_master_processor(
            seaf->session->proc_factory, "seafile-uploadfs", peer_id);
    if (!processor) {
        seaf_warning("failed to create uploadfs proc.\n");
        return -1;
    }

    ((SeafileUploadfsProc *)processor)->task = task;
    g_signal_connect(processor, "done", done_cb, task);

    if (ccnet_processor_startl(processor, NULL) < 0) {
        seaf_warning("failed to start uploadfs proc.\n");
        return -1;
    }

    return 0;
}

static void
start_fs_upload(UploadTask *task, const char *peer_id)
{
    int ret;

    if (start_uploadfs_proc(task, peer_id, (GCallback)on_fs_uploaded) < 0)
        transition_state_on_error(task, UPLOAD_TASK_ERR_UPLOAD_FS_START);
    else
        transition_state(task, task->state, UPLOAD_TASK_RT_FS);
}

static void
on_commit_uploaded(CcnetProcessor *processor, gboolean success, void *data)
{
    UploadTask *task = (UploadTask *)data;

    if (task->state == UPLOAD_TASK_STATE_CANCELED) {
        transition_state(task, task->state, UPLOAD_TASK_RT_FINISHED);
        goto out;
    }

    if (success) {
        start_fs_upload(task, processor->peer_id);
    } else if (task->state != UPLOAD_TASK_STATE_ERROR &&
               task->runtime_state == UPLOAD_TASK_RT_COMMIT) {
        upload_task_with_proc_failure(
                task, processor, UPLOAD_TASK_ERR_UPLOAD_COMMIT);
    }

out:
    g_signal_handlers_disconnect_by_func(processor, on_commit_uploaded, data);
}

static int start_upload_commit_proc(UploadTask *task, const char *peer_id, GCallback done_cb)
{
    CcnetProcessor *processor;

    processor = ccnet_proc_factory_create_remote_master_processor(
            seaf->session->proc_factory, "seafile-upload-commit", peer_id);

    ((SeafileUploadCommitProc *)processor)->task = task;
    g_signal_connect(processor, "done", done_cb, task);

    if (ccnet_processor_startl(processor, NULL) < 0) {
        seaf_warning("failed to start upload commit proc.\n");
        return -1;
    }

    return 0;
}

static void
start_commit_upload(UploadTask *task)
{
    if (start_upload_commit_proc(task, task->dest_id, (GCallback)on_commit_uploaded) < 0) {
        transition_state_on_error(task, UPLOAD_TASK_ERR_UPLOAD_COMMIT_START);
        return;
    }

    transition_state(task, task->state, UPLOAD_TASK_RT_COMMIT);

    return;
}

static void
check_upload_cb(CcnetProcessor *processor, gboolean success, void *data)
{
    UploadTask *task = data;

    /* if the user stopped or cancaled this task, stop processing. */
    if (task->state == UPLOAD_TASK_STATE_CANCELED) {
        transition_state(task, task->state, UPLOAD_TASK_RT_FINISHED);
        goto out;
    }

    if (success) {
        start_commit_upload(task);
    } else if (task->state != UPLOAD_TASK_STATE_ERROR &&
               task->runtime_state == UPLOAD_TASK_RT_CHECK) {
        upload_task_with_proc_failure(task, processor, UPLOAD_TASK_ERR_UNKNOWN);
    }

out:
    g_signal_handlers_disconnect_by_func(processor, check_upload_cb, data);
}

static int start_upload_file(UploadTask *task)
{
    const char *dest_id = task->dest_id;
    CcnetProcessor *processor;

    if (!dest_id)
        return -1;

    if (!ccnet_peer_is_ready(seaf->ccnetrpc_client, dest_id))
        return -1;

    processor = ccnet_proc_factory_create_remote_master_processor(
            seaf->session->proc_factory, "seafile-check-file-upload", dest_id);
    if (!processor) {
        seaf_warning("failed to create check-tx proc for upload file.\n");
        transition_state_on_error(task, TASK_ERR_CHECK_UPLOAD_START);
        return -1;
    }

    g_signal_connect(processor, "done", (GCallback)check_upload_cb, task);

    ((SeafileCheckFileUploadProc *)processor)->task = task;
    if (ccnet_processor_startl(processor, NULL) < 0) {
        seaf_warning("failed to start check-file-upload proc for upload.\n");
        return -1;
    }

    transition_state(task, task->state, UPLOAD_TASK_RT_CHECK);

    return 0;
}

static void transition_state_on_error(UploadTask *task, int task_errno)
{
    seaf_message("Upload File '%8.s': ('%s', '%s') --> ('%s', '%s'): %s\n",
                 task->repo_id,
                 task_state_to_str(task->state),
                 task_rt_state_to_str(task->runtime_state),
                 task_state_to_str(UPLOAD_TASK_STATE_ERROR),
                 task_rt_state_to_str(UPLOAD_TASK_RT_FINISHED),
                 task_error_str(task_errno));

    task->last_runtime_state = task->runtime_state;

    remove_task_state(task);

    g_assert(task_errno != 0);
    task->state = UPLOAD_TASK_STATE_ERROR;
    task->runtime_state = UPLOAD_TASK_RT_FINISHED;
    task->error = task_errno;

    emit_upload_done_signal(task);
}

static void *import_job(void *data)
{
    SeafRepo *repo;
    SeafCommit *head;
    SeafileCrypt *crypt = NULL;
    UploadTask *task;
    unsigned char sha1[20];

    task = (UploadTask *)data;

    if (seaf_fs_manager_index_blocks(seaf->fs_mgr, task->filepath,
                                     sha1, crypt) < 0) {
        g_warning("Failed to import file %s.\n", task->filepath);
        transition_state_on_error (task, UPLOAD_TASK_ERR_NO_SERVICE);
    }
    rawdata_to_hex(sha1, (char *)task->fs_sha1, 20);

    repo = seaf_repo_manager_get_repo(seaf->repo_mgr, task->repo_id);
    head = seaf_commit_manager_get_commit(seaf->commit_mgr, repo->head->commit_id);

    task->new_commit = seaf_commit_new(NULL, repo->id,
                                       task->fs_sha1,
                                       repo->email ? repo->email :
                                       seaf->session->base.user_name,
                                       seaf->session->base.id,
                                       "Upload File",
                                       0);
    if (seaf_commit_manager_add_commit(seaf->commit_mgr, task->new_commit) < 0) {
        seaf_commit_unref(task->new_commit);
        return data;
    }

    return data;
}

static void import_job_done(void *data)
{
    UploadTask *task;

    task = (UploadTask *)data;
    if (task->error)
        return;

    task->runtime_state = UPLOAD_TASK_RT_IMPORT;
}

static void start_import_file(UploadTask *task)
{
    ccnet_job_manager_schedule_job(seaf->job_mgr,
                                   import_job,
                                   import_job_done,
                                   task);
}

static void cancel_task(UploadTask *task)
{
    if (task->runtime_state == UPLOAD_TASK_RT_NETDOWN)
        transition_state(task, UPLOAD_TASK_STATE_CANCELED,
                         UPLOAD_TASK_RT_FINISHED);
    else
        transition_state(task, UPLOAD_TASK_STATE_CANCELED,
                         task->runtime_state);
}

static int remove_task_state(UploadTask *task)
{
    /* TODO: remove task from database */

    return 0;
}

static void emit_upload_done_signal(UploadTask *task)
{
    g_signal_emit_by_name(seaf, "repo-upload-file", task);
}

static void transition_state (UploadTask *task, int state, int rt_state)
{
    seaf_message("Upload File '%.8s': ('%s', '%s') --> ('%s', '%s')\n",
                 task->repo_id,
                 upload_task_state_to_str(task->state),
                 upload_task_rt_state_to_str(task->runtime_state),
                 upload_task_state_to_str(task->state),
                 upload_task_rt_state_to_str(task->runtime_state));

    task->last_runtime_state = task->runtime_state;

    if (rt_state == UPLOAD_TASK_RT_FINISHED) {
        remove_task_state(task);
        task->state = state;
        task->runtime_state = rt_state;

        emit_upload_done_signal(task);
        return;
    }

    if (state != task->state)
        task->state = state;
    task->runtime_state = rt_state;
}

/**
 * Upload task functions
 */
static UploadTask *seaf_upload_task_new (SeafFileUploadManager *mgr,
                                         const char *tx_id,
                                         const char *peerid,
                                         const char *filepath,
                                         const char *repoid,
                                         const char *topath)
{
    UploadTask *task;
    char *uuid;
    char *filename;

    /* never happen */
    g_return_val_if_fail (filepath != NULL, NULL);
    g_return_val_if_fail (repoid != NULL, NULL);
    g_return_val_if_fail (topath != NULL, NULL);

    filename = strrchr(filepath, '/');
    if (filename == NULL)
        filename = filepath;
    else
        filename++;

    task = g_new0 (UploadTask, 1);
    task->manager = mgr;
    memcpy (task->repo_id, repoid, 37);
    task->repo_id[36] = '\0';
    task->filepath = g_strdup (filepath);
    task->filename = g_strdup(filename);
    task->topath = g_strdup (topath);
    task->runtime_state = UPLOAD_TASK_RT_INIT;
    /* task->token = g_strdup(token); */
    task->token = g_strdup("1111");
    task->processors = g_hash_table_new_full(g_str_hash, g_str_equal,
                                             g_free, NULL);

    if (!tx_id) {
        uuid = gen_uuid();
        memcpy(task->tx_id, uuid, 37);
        g_free(uuid);
    } else {
        memcpy(task->tx_id, uuid, 37);
    }

    if (peerid)
        task->dest_id = g_strdup(peerid);

    return task;
}

static void seaf_upload_task_free(UploadTask *task)
{
    g_free(task->dest_id);
    g_free(task->filepath);
    g_free(task->filename);
    g_free(task->topath);

    g_free(task);
}

static void clean_task_for_repo (SeafFileUploadManager *mgr,
                                 const char *repoid)
{
}

void
upload_task_set_error(UploadTask *task, int error)
{
    transition_state_on_error(task, UPLOAD_TASK_ERR_UNKNOWN);
}
