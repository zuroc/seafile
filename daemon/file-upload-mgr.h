#ifndef FILE_UPLAOD_MGR_H
#define FILE_UPLAOD_MGR_H

#include <sqlite3.h>
#include <glib.h>
#include <ccnet/timer.h>
#include <ccnet/peer.h>

#include <commit-mgr.h>
#include <fs-mgr.h>

/**
 * The state that can be set by user.
 *
 * A task in NORMAL state can be canceled;
 * A task in RT_STATE_FINISHED can be remove.
 */
enum {
    UPLOAD_TASK_STATE_NORMAL = 0,
    UPLOAD_TASK_STATE_CANCELED,
    UPLOAD_TASK_STATE_FINISHED,
    UPLOAD_TASK_STATE_ERROR,
    N_UPLOAD_TASK_STATE,
};

enum {
    UPLOAD_TASK_RT_INIT = 0,
    UPLOAD_TASK_RT_CHECK,
    UPLOAD_TASK_RT_IMPORT,
    UPLOAD_TASK_RT_FS,
    UPLOAD_TASK_RT_DATA,
    UPLOAD_TASK_RT_COMMIT,
    UPLOAD_TASK_RT_UPDATE_BRANCH,
    UPLOAD_TASK_RT_FINISHED,
    UPLOAD_TASK_RT_NETDOWN,
    N_UPLOAD_TASK_RT_STATE,
};

enum UploadTaskError {
    UPLOAD_TASK_OK = 0,
    UPLOAD_TASK_ERR_UNKNOWN,
    UPLOAD_TASK_ERR_NO_SERVICE,
    UPLOAD_TASK_ERR_PROC_PERM_ERR,
    UPLOAD_TASK_ERR_CHECK_UPLOAD_START,
    UPLOAD_TASK_ERR_ACCESS_DENIED,
    UPLOAD_TASK_ERR_IMPORT_FILE,
    UPLOAD_TASK_ERR_UPLOAD_COMMIT_START,
    UPLOAD_TASK_ERR_UPLOAD_COMMIT,
    UPLOAD_TASK_ERR_UPLOAD_FS_START,
    UPLOAD_TASK_ERR_UPLOAD_FS,
    UPLOAD_TASK_ERR_LOAD_BLOCK_LIST,
    UPLOAD_TASK_ERR_START_UPDATE_BRANCH,
    N_UPLOAD_TASK_ERRORS,
};

struct _SeafFileUploadManager;

typedef struct {
    struct _SeafFileUploadManager *manager;

    char tx_id[37];
    char repo_id[37];
    char *filepath;
    char *filename;
    char *topath;
    char *token;
    char *session_token;
    int state;
    int runtime_state;
    int last_runtime_state;
    int error;
    char *dest_id;
    char fs_sha1[41];
    BlockList *block_list;
    Bitfield     active;
    gint         tx_bytes;      /* bytes transferred in the last second. */

    Bitfield     uploaded;
    int          n_uploaded;

    GList      *chunk_servers;
    GHashTable *processors;

    SeafCommit *new_commit;
} UploadTask;

struct _SeafileSession;

struct _SeafFileUploadManager {
    struct _SeafileSession *seaf;
    sqlite3 *db;

    GHashTable *upload_tasks;

    CcnetTimer *schedule_timer;
};

typedef struct _SeafFileUploadManager SeafFileUploadManager;

SeafFileUploadManager *seaf_file_upload_manager_new (struct _SeafileSession *seaf);

int seaf_file_upload_manager_start (SeafFileUploadManager *mgr);
int seaf_file_upload_manager_init (SeafFileUploadManager *mgr);

int
seaf_file_upload_manager_add_task (SeafFileUploadManager *mgr,
                                   const char *filepath,
                                   const char *peerid,
                                   const char *repoid,
                                   const char *topath,
                                   GError **error);

void
upload_task_set_error(UploadTask *task, int error);

#endif /* FILE_UPLAOD_MGR_H */
