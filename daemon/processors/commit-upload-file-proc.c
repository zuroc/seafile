#include <string.h>

#include <ccnet.h>

#include "common.h"
#include "seafile-session.h"
#include "vc-common.h"
#include "seafile-crypt.h"
#include "log.h"
#include "utils.h"

#include "commit-upload-file-proc.h"

G_DEFINE_TYPE(SeafileCommitUploadFileProc, seafile_commit_upload_file_proc, CCNET_TYPE_PROCESSOR)

static int start (CcnetProcessor *processor, int argc, char **argv);
static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen);

static void
release_resource(CcnetProcessor *processor)
{
    CCNET_PROCESSOR_CLASS (seafile_commit_upload_file_proc_parent_class)->release_resource (processor);
}

static void seafile_commit_upload_file_proc_class_init(SeafileCommitUploadFileProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS(klass);

    proc_class->name = "commit-upload-file-proc";
    proc_class->start = start;
    proc_class->handle_response = handle_response;
    proc_class->release_resource = release_resource;
}

static void
seafile_commit_upload_file_proc_init(SeafileCommitUploadFileProc *processor)
{
}

static int
start (CcnetProcessor *processor, int argc, char **argv)
{
    SeafileCommitUploadFileProc *proc = (SeafileCommitUploadFileProc *)processor;
    UploadTask *task = proc->task;
    GString *buf;

    buf = g_string_new(NULL);
    g_string_append_printf(buf,
            "remote %s seafile-commit-upload-file-slave %s %s %s %s %s",
            processor->peer_id, task->repo_id, task->fs_sha1,
            task->topath, task->filename, task->session_token);
    ccnet_processor_send_request(processor, buf->str);
    g_string_free(buf, TRUE);

    return 0;
}

static void
handle_response (CcnetProcessor *processor,
                 char *code, char *code_msg,
                 char *content, int clen)
{
    if (memcpy(code, SC_OK, 3) == 0)
        ccnet_processor_done(processor, TRUE);
    else
        ccnet_processor_done(processor, FALSE);
}
