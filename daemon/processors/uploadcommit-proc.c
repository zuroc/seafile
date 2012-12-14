/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#define DEBUG_FLAG SEAFILE_DEBUG_TRANSFER
#include "log.h"

#include <fcntl.h>

#include <ccnet.h>
#include "net.h"
#include "utils.h"

#include "seafile-session.h"
#include "uploadcommit-proc.h"
#include "processors/objecttx-common.h"

#define SC_COMMIT   "301"
#define SS_COMMIT   "Send Commit"
#define SC_DONE     "302"
#define SS_DONE     "Done"

static int start (CcnetProcessor *processor, int argc, char **argv);
static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen);


G_DEFINE_TYPE (SeafileUploadCommitProc, seafile_upload_commit_proc, CCNET_TYPE_PROCESSOR)

static void
release_resource (CcnetProcessor *processor)
{
}

static void
seafile_upload_commit_proc_class_init (SeafileUploadCommitProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "upload-commit-proc";
    proc_class->start = start;
    proc_class->handle_response = handle_response;
    proc_class->release_resource = release_resource;
}

static void
seafile_upload_commit_proc_init (SeafileUploadCommitProc *processor)
{
}

static int
start (CcnetProcessor *processor, int argc, char **argv)
{
    GString *buf;
    UploadTask *task = ((SeafileUploadCommitProc *)processor)->task;

    buf = g_string_new (NULL);
    g_string_printf (buf, "remote %s seafile-upload-commit-slave %s",
                     processor->peer_id, task->session_token);
    ccnet_processor_send_request (processor, buf->str);
    g_string_free (buf, TRUE);

    return 0;
}

static void send_commit(CcnetProcessor *processor, UploadTask *task)
{
    char *data;
    int len;
    ObjectPack *pack = NULL;
    int pack_size;

    if (seaf_obj_store_read_obj(seaf->commit_mgr->obj_store,
                        task->new_commit->commit_id, (void**)&data, &len) < 0) {
        g_warning ("Failed to read commit %s.\n", task->new_commit->commit_id);
        goto fail;
    }

    pack_size = sizeof(ObjectPack) + len;
    pack = malloc(pack_size);
    memcpy(pack->id, task->new_commit->commit_id, 41);
    memcpy(pack->object, data, len);

    ccnet_processor_send_update(processor, SC_COMMIT, SS_COMMIT,
                                (char *)pack, pack_size);
    g_free(data);
    free(pack);
    return;

fail:
    ccnet_processor_send_update(processor, SC_NOT_FOUND, SS_NOT_FOUND,
                                task->new_commit->commit_id, 41);
}

static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen)
{
    SeafileUploadCommitProc *proc = (SeafileUploadCommitProc *)processor;
    UploadTask *task = proc->task;

    if (memcmp(code, SC_OK, 3) == 0) {
        send_commit(processor, task);
        return 0;
    } else if (memcmp(code, SC_DONE, 3) == 0) {
        ccnet_processor_done(processor, TRUE);
        return 0;
    }

    g_warning ("Bad response: %s %s.\n", code, code_msg);
    ccnet_processor_done (processor, FALSE);
}
