#include <string.h>

#include <ccnet.h>

#include "common.h"
#include "seafile-session.h"
#include "vc-common.h"
#include "seafile-crypt.h"
#define DEBUG_FLAG SEAFILE_DEBUG_TRANSFER
#include "log.h"
#include "utils.h"

#include "uploadfs-slave-proc.h"
#include "processors/objecttx-common.h"

#define MAX_NUM_BATCH  64

enum {
    RECV_FS,
    RECV_OBJECT,
};

typedef struct {
    char fs_sha1[41];

    char *obj_seg;
    int obj_seg_len;

    int inspect_objects;
    int pending_objects;
    char buf[4096];
    char *bufptr;
    int  n_batch;
    GHashTable  *fs_objects;

    gboolean registered;
    guint32  reader_id;
    guint32  writer_id;
    guint32  stat_id;
} SeafileUploadfsSlaveProcPriv;

#define GET_PRIV(o) \
    (G_TYPE_INSTANCE_GET_PRIVATE((o), SEAFILE_TYPE_UPLOADFS_SLAVE_PROC, SeafileUploadfsSlaveProcPriv))

#define USE_PRIV \
     SeafileUploadfsSlaveProcPriv *priv = GET_PRIV(processor);

G_DEFINE_TYPE(SeafileUploadfsSlaveProc, seafile_uploadfs_slave_proc, CCNET_TYPE_PROCESSOR)

static int start(CcnetProcessor *processor, int argc, char **argv);
static void handle_update(CcnetProcessor *processor,
                            char *code, char *code_msg,
                            char *content, int clen);

static void
release_resource(CcnetProcessor *processor)
{
    CCNET_PROCESSOR_CLASS (seafile_uploadfs_slave_proc_parent_class)->release_resource (processor);
}

static void seafile_uploadfs_slave_proc_class_init(SeafileUploadfsSlaveProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS(klass);

    proc_class->name = "uploadfs-slave-proc";
    proc_class->start = start;
    proc_class->handle_update = handle_update;
    proc_class->release_resource = release_resource;

    g_type_class_add_private (klass, sizeof (SeafileUploadfsSlaveProcPriv));
}

static void
seafile_uploadfs_slave_proc_init(SeafileUploadfsSlaveProc *processor)
{
}

inline static void
request_object_batch_begin (SeafileUploadfsSlaveProcPriv *priv)
{
    priv->bufptr = priv->buf;
    priv->n_batch = 0;
}

inline static void
request_object_batch_flush (CcnetProcessor *processor,
                            SeafileUploadfsSlaveProcPriv *priv)
{
    if (priv->bufptr == priv->buf)
        return;
    *priv->bufptr = '\0';       /* add ending '\0' */
    priv->bufptr++;
    ccnet_processor_send_response (processor, SC_GET_OBJECT, SS_GET_OBJECT,
                                   priv->buf, priv->bufptr - priv->buf);

    /* Clean state */
    priv->n_batch = 0;
    priv->bufptr = priv->buf;
}

inline static void
request_object_batch (CcnetProcessor *processor,
                      SeafileUploadfsSlaveProcPriv *priv, const char *id)
{
    g_assert(priv->bufptr - priv->buf <= (4096-41));

    if (g_hash_table_lookup(priv->fs_objects, id))
        return;

    memcpy (priv->bufptr, id, 40);
    priv->bufptr += 40;
    *priv->bufptr = '\n';
    priv->bufptr++;

    g_hash_table_insert (priv->fs_objects, g_strdup(id), (gpointer)1);
    /* Flush when too many objects batched. */
    if (++priv->n_batch == MAX_NUM_BATCH)
        request_object_batch_flush (processor, priv);
    ++priv->pending_objects;
}

static int
check_seafdir (CcnetProcessor *processor, SeafDir *dir)
{
    USE_PRIV;
    GList *ptr;
    SeafDirent *dent;

    for (ptr = dir->entries; ptr != NULL; ptr = ptr->next) {
        dent = ptr->data;

        if (strcmp (dent->id, EMPTY_SHA1) == 0)
            continue;

#ifdef DEBUG
        seaf_debug ("[recvfs] Inspect object %s.\n", dent->id);
#endif

        if (S_ISDIR(dent->mode)) {
            if (seaf_obj_store_async_read (seaf->fs_mgr->obj_store,
                                           priv->reader_id,
                                           dent->id) < 0) {
                g_warning ("[recvfs] Failed to start async read of %s.\n",
                           dent->id);
                goto bad;
            }
        } else {
            /* For file, we just need to check existence. */
            if (seaf_obj_store_async_stat (seaf->fs_mgr->obj_store,
                                           priv->stat_id,
                                           dent->id) < 0) {
                g_warning ("[recvfs] Failed to start async stat of %s.\n",
                           dent->id);
                goto bad;
            }
        }
        ++(priv->inspect_objects);
    }

    return 0;

bad:
    ccnet_processor_send_response (processor, SC_BAD_OBJECT, SS_BAD_OBJECT,
                                   NULL, 0);
    ccnet_processor_done (processor, FALSE);
    return -1;
}

static void
on_seafdir_read (OSAsyncResult *res, void *cb_data)
{
    CcnetProcessor *processor = cb_data;
    SeafDir *dir;
    USE_PRIV;

    --(priv->inspect_objects);

    if (!res->success) {
        request_object_batch (processor, priv, res->obj_id);
        return;
    }

#ifdef DEBUG
    seaf_debug ("[recvfs] Read seafdir %s.\n", res->obj_id);
#endif

    dir = seafile_from_data (res->obj_id, res->data, res->len);
    if (!dir) {
        g_warning ("[recvfs] Corrupt dir object %s.\n", res->obj_id);
        request_object_batch (processor, priv, res->obj_id);
        return;
    }
    check_seafdir (processor, dir);
    seaf_dir_free (dir);
}

static void
on_seafile_stat (OSAsyncResult *res, void *cb_data)
{
    CcnetProcessor *processor = cb_data;
    USE_PRIV;

    --(priv->inspect_objects);

#ifdef DEBUG
    seaf_debug ("[recvfs] Stat seafile %s.\n", res->obj_id);
#endif

    if (!res->success)
        request_object_batch (processor, priv, res->obj_id);
}

static void
on_fs_write (OSAsyncResult *res, void *cb_data)
{
    CcnetProcessor *processor = cb_data;

    if (!res->success) {
        g_warning ("[recvfs] Failed to write %s.\n", res->obj_id);
        ccnet_processor_send_response (processor, SC_BAD_OBJECT, SS_BAD_OBJECT,
                                       NULL, 0);
        ccnet_processor_done (processor, FALSE);
    }

#ifdef DEBUG
    seaf_debug ("[recvfs] Wrote fs object %s.\n", res->obj_id);
#endif
}

static void
register_async_io(CcnetProcessor *processor)
{
    USE_PRIV;

    priv->registered = TRUE;
    priv->reader_id = seaf_obj_store_register_async_read (seaf->fs_mgr->obj_store,
                                                          on_seafdir_read,
                                                          processor);
    priv->stat_id = seaf_obj_store_register_async_stat (seaf->fs_mgr->obj_store,
                                                          on_seafile_stat,
                                                          processor);
    priv->writer_id = seaf_obj_store_register_async_write (seaf->fs_mgr->obj_store,
                                                           on_fs_write,
                                                           processor);
}

static int
start (CcnetProcessor *processor, int argc, char **argv)
{
    char *session_token;

    if (argc != 1) {
        ccnet_processor_send_response(processor, SC_BAD_ARGS,
                                      SS_BAD_ARGS, NULL, 0);
        ccnet_processor_done(processor, FALSE);
        return -1;
    }

    session_token = argv[0];
    if (seaf_token_manager_verify_token(seaf->token_mgr,
                                        processor->peer_id,
                                        session_token, NULL) != 0) {
        ccnet_processor_send_response(processor,
                                      SC_ACCESS_DENIED, SS_ACCESS_DENIED,
                                      NULL, 0);
        ccnet_processor_done(processor, FALSE);
        return -1;
    }

    ccnet_processor_send_response(processor, SC_OK, SS_OK, NULL, 0);
    processor->state = RECV_FS;
    register_async_io(processor);
    return 0;
}

static void
recv_fs(CcnetProcessor *processor, char *content, int clen)
{
    USE_PRIV;

    if (clen != 41) {
        ccnet_processor_send_response(processor,
                                      SC_BAD_ARGS, SS_BAD_ARGS,
                                      NULL, 0);
        ccnet_processor_done(processor, FALSE);
        return;
    }

    memcpy(priv->fs_sha1, content, 40);
    priv->fs_sha1[40] = '\0';

    ccnet_processor_send_response(processor,
                                  SC_GET_OBJECT, SS_GET_OBJECT,
                                  NULL, 0);
    processor->state = RECV_OBJECT;
}

static int
save_fs_object(CcnetProcessor *processor, ObjectPack *pack, int len)
{
    USE_PRIV;

    return seaf_obj_store_async_write(seaf->fs_mgr->obj_store,
                                      priv->writer_id,
                                      pack->id,
                                      pack->object,
                                      len - 41);
}

static int
recv_fs_object(CcnetProcessor *processor, char *content, int clen)
{
    ObjectPack *pack = (ObjectPack *)content;
    uint32_t type;

    if (clen < sizeof(ObjectPack)) {
        g_warning("invalid object id.\n");
        goto bad;
    }

    seaf_debug("[uploadfs-slave] Recv fs object %.8s.\n", pack->id);

    type = seaf_metadata_type_from_data(pack->object, clen);
    if (type == SEAF_METADATA_TYPE_FILE) {
    } else if (type == SEAF_METADATA_TYPE_DIR) {
        g_warning("We never upload a dir.\n");
        goto bad;
    } else {
        g_warning ("Invalid object type.\n");
        goto bad;
    }

    if (save_fs_object (processor, pack, clen) < 0) {
        goto bad;
    }

    return 0;

bad:
    ccnet_processor_send_response (processor, SC_BAD_OBJECT,
                                   SS_BAD_OBJECT, NULL, 0);
    g_warning ("[uploadfs-slave] Bad fs object received.\n");
    ccnet_processor_done (processor, FALSE);

    return -1;
}

static void
recv_fs_object_seg(CcnetProcessor *processor, char *content, int clen)
{
    USE_PRIV;

    /* Append the received object segment to the end */
    priv->obj_seg = g_realloc(priv->obj_seg, priv->obj_seg_len + clen);
    memcpy(priv->obj_seg + priv->obj_seg_len, content, clen);

    seaf_debug ("[uploadfs-slave] Get obj seg: <id= %40s, offset= %d, lenth= %d>\n",
                priv->obj_seg, priv->obj_seg_len, clen);

    priv->obj_seg_len += clen;
}

static void
process_fs_object_seg(CcnetProcessor *processor)
{
    USE_PRIV;

    if (recv_fs_object(processor, priv->obj_seg, priv->obj_seg_len) == 0) {
        g_free(priv->obj_seg);
        priv->obj_seg = NULL;
        priv->obj_seg_len = 0;
    }
}

static void
handle_update (CcnetProcessor *processor,
                 char *code, char *code_msg,
                 char *content, int clen)
{
    switch (processor->state) {
    case RECV_FS:
        if (strncmp(code, SC_FS_SHA1, 3) == 0) {
            recv_fs(processor, content, clen);
        }
        break;
    case RECV_OBJECT:
        if (strncmp(code, SC_OBJ_SEG, 3) == 0) {
            recv_fs_object_seg(processor, content, clen);
        } else if (strncmp(code, SC_OBJ_SEG_END, 3) == 0) {
            recv_fs_object_seg(processor, content, clen);
            process_fs_object_seg(processor);
            ccnet_processor_send_response(processor, SC_END, SS_END, NULL, 0);
            ccnet_processor_done(processor, TRUE);
        } else if (strncmp(code, SC_OBJECT, 3) == 0) {
            recv_fs_object(processor, content, clen);
            ccnet_processor_send_response(processor, SC_END, SS_END, NULL, 0);
            ccnet_processor_done(processor, TRUE);
        } else {
            g_warning("Bad response: %s %s\n", code, code_msg);
            ccnet_processor_send_response(processor,
                                         SC_BAD_UPDATE_CODE, SS_BAD_UPDATE_CODE,
                                         NULL, 0);
            ccnet_processor_done(processor, FALSE);
        }
        break;
    default:
        g_assert(0);
    }
}
