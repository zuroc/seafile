#include <string.h>

#include <ccnet.h>

#include "common.h"
#include "seafile-session.h"
#include "vc-common.h"
#include "seafile-crypt.h"
#include "log.h"
#include "utils.h"

#include "commit-upload-file-slave-proc.h"
#include "processors/objecttx-common.h"

#define SC_FAILURE  "401"
#define SS_FAILURE  "Commit Failure"

G_DEFINE_TYPE(SeafileCommitUploadFileSlaveProc, seafile_commit_upload_file_slave_proc, CCNET_TYPE_PROCESSOR)

typedef struct {
    char repo_id[37];
    char fs_sha1[41];
    char *topath;
    char *filename;

    char *rsp_code;
    char *rsp_code_msg;
} SeafileCommitUploadFileSlaveProcPriv;

#define GET_PRIV(o) \
    (G_TYPE_INSTANCE_GET_PRIVATE ((o), SEAFILE_TYPE_COMMIT_UPLOAD_FILE_SLAVE_PROC, SeafileCommitUploadFileSlaveProcPriv))

#define USE_PRIV \
    SeafileCommitUploadFileSlaveProcPriv *priv = GET_PRIV(processor)

static int start (CcnetProcessor *processor, int argc, char **argv);
static void handle_update (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen);
static void *commit_upload_file(void *vprocessor);
static void commit_upload_file_cb(void *result);

static void
release_resource(CcnetProcessor *processor)
{
    USE_PRIV;

    g_free(priv->topath);
    g_free(priv->filename);

    CCNET_PROCESSOR_CLASS (seafile_commit_upload_file_slave_proc_parent_class)->release_resource (processor);
}

static void seafile_commit_upload_file_slave_proc_class_init(SeafileCommitUploadFileSlaveProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS(klass);

    proc_class->name = "commit-upload-file-slave-proc";
    proc_class->start = start;
    proc_class->handle_update = handle_update;
    proc_class->release_resource = release_resource;

    g_type_class_add_private (klass, sizeof (SeafileCommitUploadFileSlaveProcPriv));
}

static void
seafile_commit_upload_file_slave_proc_init(SeafileCommitUploadFileSlaveProc *processor)
{
}

static int
start (CcnetProcessor *processor, int argc, char **argv)
{
    SeafileCommitUploadFileSlaveProc *proc = (SeafileCommitUploadFileSlaveProc *)processor;
    USE_PRIV;
    char *session_token;

    if (argc != 5) {
        ccnet_processor_send_response(processor, SC_BAD_ARGS, SS_BAD_ARGS, NULL, 0);
        ccnet_processor_done(processor, FALSE);
        return -1;
    }

    if (strlen(argv[0]) != 36 || strlen(argv[1]) != 40) {
        ccnet_processor_send_response(processor, SC_BAD_ARGS, SS_BAD_ARGS, NULL, 0);
        ccnet_processor_done(processor, FALSE);
        return -1;
    }

    memcpy(priv->repo_id, argv[0], 36);
    priv->repo_id[36] = '\0';
    memcpy(priv->fs_sha1, argv[1], 40);
    priv->fs_sha1[40] = '\0';
    priv->topath = g_strdup(argv[2]);
    priv->filename = g_strdup(argv[3]);
    session_token = argv[4];

    if (seaf_token_manager_verify_token(seaf->token_mgr,
                                        processor->peer_id,
                                        session_token, NULL) != 0) {
        ccnet_processor_send_response(processor,
                                      SC_ACCESS_DENIED, SS_ACCESS_DENIED,
                                      NULL, 0);
        ccnet_processor_done(processor, FALSE);
        return -1;
    }

    ccnet_processor_thread_create(processor, commit_upload_file,
                                  commit_upload_file_cb, processor);

    return 0;
}

static void *
commit_upload_file(void *vprocessor)
{
    CcnetProcessor *processor = (CcnetProcessor *)vprocessor;
    USE_PRIV;
    SeafDirent *new_dent = NULL;
    SeafRepo *repo = NULL;
    SeafCommit *head_commit = NULL;
    SeafCommit *new_commit = NULL;
    char *root_id = NULL;
    char buf[PATH_MAX];

    repo = seaf_repo_manager_get_repo(seaf->repo_mgr, priv->repo_id);
    if (!repo) {
        goto err;
    }

    head_commit = seaf_commit_manager_get_commit(seaf->commit_mgr,
                                                 repo->head->commit_id);
    if (!head_commit) {
        goto err;
    }

    new_dent = seaf_dirent_new(priv->fs_sha1, S_IFREG, priv->filename);
    root_id = do_post_file(head_commit->root_id, priv->topath, new_dent);
    if (!root_id) {
        priv->rsp_code = SC_FAILURE;
        priv->rsp_code_msg = SS_FAILURE;
        goto err;
    }

    snprintf(buf, PATH_MAX, "Added \"%s\"", "test");
    new_commit = seaf_commit_new(NULL, repo->id, root_id, NULL, EMPTY_SHA1, buf, 0);
    new_commit->parent_id = g_strdup(head_commit->commit_id);
    seaf_repo_to_commit(repo, new_commit);

    if (seaf_commit_manager_add_commit (seaf->commit_mgr, new_commit) < 0) {
        seaf_warning ("Failed to add commit.\n");
        priv->rsp_code = SC_FAILURE;
        priv->rsp_code_msg = SS_FAILURE;
        goto err;
    }

retry:
    seaf_branch_set_commit(repo->head, new_commit->commit_id);
    if (seaf_branch_manager_test_and_update_branch(seaf->branch_mgr,
                                                   repo->head,
                                                   head_commit->commit_id) < 0)
    {
        seaf_message ("Concurrent branch update, retry.\n");

        seaf_repo_unref (repo);
        repo = NULL;

        repo = seaf_repo_manager_get_repo (seaf->repo_mgr, priv->repo_id);
        if (!repo) {
            seaf_warning ("Repo %s doesn't exist.\n", priv->repo_id);
            priv->rsp_code = SC_FAILURE;
            priv->rsp_code_msg = SS_FAILURE;
            goto err;
        }

        goto retry;
    }

    priv->rsp_code = SC_OK;
    priv->rsp_code_msg = SS_OK;

err:
    seaf_commit_unref (new_commit);
    seaf_repo_unref (repo);

    return vprocessor;
}

static void
commit_upload_file_cb(void *result)
{
    CcnetProcessor *processor = (CcnetProcessor *)result;
    USE_PRIV;

    ccnet_processor_send_response (processor,
                                   priv->rsp_code, priv->rsp_code_msg,
                                   NULL, 0);
    ccnet_processor_done (processor, TRUE);
}

static void
handle_update (CcnetProcessor *processor,
                 char *code, char *code_msg,
                 char *content, int clen)
{
}
