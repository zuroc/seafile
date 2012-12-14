#include <string.h>

#include <ccnet.h>

#include "common.h"
#include "seafile-session.h"
#include "vc-common.h"
#include "seafile-crypt.h"
#define DEBUG_FLAG SEAFILE_DEBUG_TRANSFER
#include "log.h"
#include "utils.h"

#include "uploadfs-proc.h"
#include "processors/objecttx-common.h"

enum {
    SEND_FS,
    SEND_OBJECT,
};

G_DEFINE_TYPE(SeafileUploadfsProc, seafile_uploadfs_proc, CCNET_TYPE_PROCESSOR)

static int start(CcnetProcessor *processor, int argc, char **argv);
static void handle_response(CcnetProcessor *processor,
                            char *code, char *code_msg,
                            char *content, int clen);

static void
release_resource(CcnetProcessor *processor)
{
    CCNET_PROCESSOR_CLASS (seafile_uploadfs_proc_parent_class)->release_resource (processor);
}

static void seafile_uploadfs_proc_class_init(SeafileUploadfsProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS(klass);

    proc_class->name = "uploadfs-proc";
    proc_class->start = start;
    proc_class->handle_response = handle_response;
    proc_class->release_resource = release_resource;
}

static void
seafile_uploadfs_proc_init(SeafileUploadfsProc *processor)
{
}

static int
start (CcnetProcessor *processor, int argc, char **argv)
{
    GString *buf;
    SeafileUploadfsProc *proc = (SeafileUploadfsProc *)processor;
    UploadTask *task = proc->task;

    buf = g_string_new(NULL);
    g_string_printf(buf, "remote %s seafile-uploadfs-slave %s",
                    processor->peer_id, task->session_token);
    ccnet_processor_send_request(processor, buf->str);
    g_string_free(buf, TRUE);

    processor->state = SEND_FS;
    return 0;
}

static void
send_fs(CcnetProcessor *processor)
{
    SeafileUploadfsProc *proc = (SeafileUploadfsProc *)processor;
    UploadTask *task = proc->task;

    ccnet_processor_send_update(processor, SC_FS_SHA1, SS_FS_SHA1,
                                task->fs_sha1, 41);
    processor->state = SEND_OBJECT;
}

static void
send_fs_object(CcnetProcessor *processor)
{
    SeafileUploadfsProc *proc = (SeafileUploadfsProc *)processor;
    UploadTask *task = proc->task;
    ObjectPack *pack = NULL;
    char *data;
    int len;
    int pack_size;

    if (seaf_obj_store_read_obj(seaf->fs_mgr->obj_store,
                                task->fs_sha1, (void **)&data, &len) < 0) {
        g_warning("Failed to read fs object %s.\n", task->fs_sha1);
        goto fail;
    }

    pack_size = sizeof(ObjectPack) + len;
    pack = malloc(pack_size);
    memcpy (pack->id, task->fs_sha1, 41);
    memcpy (pack->object, data, len);

    if (pack_size <= MAX_OBJ_SEG_SIZE) {
        ccnet_processor_send_update(processor, SC_OBJECT, SS_OBJECT,
                                    (char *)pack, pack_size);
    } else {
        int offset, n;

        offset = 0;
        while (offset < pack_size) {
            n = MIN(pack_size - offset, MAX_OBJ_SEG_SIZE);

            if (offset + n < pack_size) {
                ccnet_processor_send_update (processor,
                                             SC_OBJ_SEG, SS_OBJ_SEG,
                                             (char *)pack + offset, n);
            } else {
                ccnet_processor_send_update (processor,
                                             SC_OBJ_SEG_END, SS_OBJ_SEG_END,
                                             (char *)pack + offset, n);
            }

            seaf_debug ("Sent object %s segment<total = %d, offset = %d, n = %d>\n",
                        task->fs_sha1, pack_size, offset, n);

            offset += n;
        }
    }

    return;

fail:
    ccnet_processor_send_update(processor, SC_NOT_FOUND, SS_NOT_FOUND,
                                task->fs_sha1, 41);
    ccnet_processor_done(processor, FALSE);
}

static void
handle_response (CcnetProcessor *processor,
                 char *code, char *code_msg,
                 char *content, int clen)
{
    SeafileUploadfsProc *proc = (SeafileUploadfsProc *)processor;
    UploadTask *task = proc->task;

    switch (processor->state) {
    case SEND_FS:
        if (strncmp(code, SC_OK, 3) == 0) {
            send_fs(processor);
            return;
        }
        break;
    case SEND_OBJECT:
        if (strncmp(code, SC_GET_OBJECT, 3) == 0) {
            send_fs_object(processor);
            return;
        } else if (strncmp(code, SC_END, 3) == 0) {
            seaf_debug ("Send fs objects end.\n");
            ccnet_processor_done (processor, TRUE);
            return;
        }
        break;
    default:
        g_assert(0);
    }

    seaf_warning("Bad response: %s %s.\n", code, code_msg);
    if (strncmp(code, SC_ACCESS_DENIED, 3) == 0)
        upload_task_set_error(task, UPLOAD_TASK_ERR_ACCESS_DENIED);
    ccnet_processor_done(processor, FALSE);
}
