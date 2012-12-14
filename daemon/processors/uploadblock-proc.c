#include <string.h>

#include <ccnet.h>

#include <net.h>
#include "common.h"
#include "seafile-session.h"
#include "vc-common.h"
#include "seafile-crypt.h"
#define DEBUG_FLAG SEAFILE_DEBUG_TRANSFER
#include "log.h"
#include "utils.h"

#include "uploadblock-proc.h"

#define SC_SEND_PORT    "301"
#define SS_SEND_PORT    "PORT"
#define SC_GET_PORT     "302"
#define SS_GET_PORT     "GET PORT"
#define SC_GET_BLOCK    "303"
#define SS_GET_BLOCK    "GET BLOCK"
#define SC_BBITMAP      "304"
#define SS_BBITMAP      "BLOCK BITMAP"
#define SC_ACK          "305"
#define SS_ACK          "BLOCK OK"
#define SC_BLOCKLIST    "306"
#define SS_BLOCKLIST    "BLOCK LIST"

#define SC_BAD_BLK_REQ      "405"
#define SS_BAD_BLK_REQ      "BAD BLOCK REQUEST"
#define SC_BAD_BL           "408"
#define SS_BAD_BL           "BAD BLOCK LIST"

#define SC_ACCESS_DENIED "410"
#define SS_ACCESS_DENIED "Access denied"

enum {
    REQUEST_SENT,
    BLOCKLIST_SENT,
    GET_PORT,
    ESTABLISHED,
};

typedef struct {
    ThreadData      *tdata;
    int              bm_offset;
    GHashTable      *block_hash;
} UploadBlockProcPriv;

#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), SEAFILE_TYPE_UPLOAD_BLOCK_PROC, UploadBlockProcPriv))

#define USE_PRIV \
    UploadBlockProcPriv *priv = GET_PRIV(processor);

G_DEFINE_TYPE(SeafileUploadBlockProc, seafile_upload_block_proc, CCNET_TYPE_PROCESSOR)

static int start(CcnetProcessor *processor, int argc, char **argv);
static void handle_response(CcnetProcessor *processor,
                            char *code, char *code_msg,
                            char *content, int clen);

static void
release_resource(CcnetProcessor *processor)
{
    CCNET_PROCESSOR_CLASS (seafile_upload_block_proc_parent_class)->release_resource (processor);
}

static void seafile_upload_block_proc_class_init(SeafileUploadBlockProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS(klass);

    proc_class->name = "uploadblock-proc";
    proc_class->start = start;
    proc_class->handle_response = handle_response;
    proc_class->release_resource = release_resource;

    g_type_class_add_private (klass, sizeof (UploadBlockProcPriv));
}

static void
seafile_upload_block_proc_init(SeafileUploadBlockProc *processor)
{
}

static void
send_block_rsp (int cevent_id, int block_idx, int tx_bytes, int tx_time)
{
    BlockResponse *blk_rsp = g_new0 (BlockResponse, 1);
    blk_rsp->block_idx = block_idx;
    blk_rsp->tx_bytes = tx_bytes;
    blk_rsp->tx_time = tx_time;
    cevent_manager_add_event (seaf->ev_mgr, 
                              cevent_id,
                              (void *)blk_rsp);
}

static int
send_block_packet (ThreadData *tdata,
                   int block_idx,
                   const char *block_id,
                   BlockHandle *handle, 
                   evutil_socket_t sockfd)
{
    SeafBlockManager *block_mgr = seaf->block_mgr;
    BlockMetadata *md;
    uint32_t size;
    BlockPacket pkt;
    char buf[1024];
    int n;

    md = seaf_block_manager_stat_block_by_handle (block_mgr, handle);
    if (!md) {
        seaf_warning ("Failed to stat block %s.\n", block_id);
        return -1;
    }
    size = md->size;
    g_free (md);

    pkt.block_size = htonl (size);
    pkt.block_idx = htonl ((uint32_t) block_idx);
    memcpy (pkt.block_id, block_id, 41);
    if (sendn (sockfd, &pkt, sizeof(pkt)) < 0) {
        seaf_warning ("Failed to write socket: %s.\n", 
                   evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
        return -1;
    }

    while (1) {
        n = seaf_block_manager_read_block (block_mgr, handle, buf, 1024);
        if (n <= 0)
            break;
        if (sendn (sockfd, buf, n) < 0) {
            seaf_warning ("Failed to write block %s: %s.\n", block_id, 
                       evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
            return -1;
        }
        /* Update global transferred bytes. */
        g_atomic_int_add (&(tdata->task->tx_bytes), n);
    }
    if (n < 0) {
        seaf_warning ("Failed to write block %s: %s.\n", block_id, 
                   evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
        return -1;
    }

    send_block_rsp (tdata->cevent_id, block_idx, 0, 0);

    return size;
}

static int
upload_blocks (ThreadData *tdata)
{
    SeafBlockManager *block_mgr = seaf->block_mgr;
    BlockRequest blk_req;
    BlockHandle *handle;
    int         n;
    int         n_sent;

    while (1) {
        n = pipereadn (tdata->task_pipe[0], &blk_req, sizeof(blk_req));
        if (n == 0) {
            seaf_debug ("Processor exited. Worker thread exits now.\n");
            return -1;
        }
        if (n != sizeof(blk_req)) {
            seaf_warning ("read task pipe incorrect.\n");
            return -1;
        }

        handle = seaf_block_manager_open_block (block_mgr, 
                                                blk_req.block_id, BLOCK_READ);
        if (!handle) {
            seaf_warning ("[send block] failed to open block %s.\n", 
                       blk_req.block_id);
            return -1;
        }

        n_sent = send_block_packet (tdata, blk_req.block_idx, blk_req.block_id, 
                                    handle, tdata->data_fd);
        if (n_sent < 0)
            return -1;

        seaf_block_manager_close_block (block_mgr, handle);
        seaf_block_manager_block_handle_free (block_mgr, handle);
    }

    return 0;
}

static void
upload_blocks_cb(CEvent *event, void *vprocessor)
{
    SeafileUploadBlockProc *proc = vprocessor;
    BlockResponse *blk_rsp = event->data;

    if (blk_rsp->block_idx >= 0)
        --(proc->pending_blocks);

    g_free (blk_rsp);
}

static int
master_block_proc_start (CcnetProcessor *processor,
                         UploadTask *tx_task,
                         const char *remote_processor_name,
                         Bitfield *active,
                         Bitfield *block_bitmap)
{
    GString *buf;
    if (!tx_task || !tx_task->session_token) {
        seaf_warning ("upload task not set.\n");
        return -1;
    }

    BitfieldConstruct (active,
                       tx_task->block_list->block_map.bitCount);
    BitfieldConstruct (block_bitmap,
                       tx_task->block_list->block_map.bitCount);

    buf = g_string_new (NULL);
    g_string_printf (buf, "remote %s %s %s", 
                     processor->peer_id,
                     remote_processor_name,
                     tx_task->session_token);
                         
    ccnet_processor_send_request (processor, buf->str);
    g_string_free (buf, TRUE);

    return 0;
}

static void
prepare_thread_data (CcnetProcessor *processor,
                     TransferFunc tranfer_func,
                     ThreadEventHandler handler)
{
    USE_PRIV;

    priv->tdata = g_new0 (ThreadData, 1);
    priv->tdata->task_pipe[0] = -1;
    priv->tdata->task_pipe[1] = -1;
    priv->tdata->transfer_func = tranfer_func;
    priv->tdata->processor = processor;

    priv->tdata->cevent_id = cevent_manager_register (seaf->ev_mgr,
                                                      handler,
                                                      processor);
}

static int
start (CcnetProcessor *processor, int argc, char **argv)
{
    USE_PRIV;
    SeafileUploadBlockProc *proc = (SeafileUploadBlockProc *)processor;
    
    if (master_block_proc_start(processor, proc->task,
                                "seafile-upload-block-slave",
                                &proc->active,
                                &proc->block_bitmap) < 0) {
        ccnet_processor_done (processor, FALSE);
        return -1;
    }

    prepare_thread_data (processor, upload_blocks, upload_blocks_cb);
    priv->tdata->task = proc->task;

    return 0;
}

static void
send_block_list (CcnetProcessor *processor)
{
    SeafileUploadBlockProc *proc = (SeafileUploadBlockProc *)processor;
    BlockList *bl = proc->task->block_list;
    int i, n = 0;
    char buf[MAX_BL_LEN * 41];
    int len = 0;

    for (i = 0; i < bl->n_blocks; ++i) {
        memcpy (&buf[len], g_ptr_array_index(bl->block_ids, i), 41);
        len += 41;

        if (++n == MAX_BL_LEN) {
            ccnet_processor_send_update (processor, SC_BLOCKLIST, SS_BLOCKLIST,
                                         (char *)buf, len);
            n = 0;
            len = 0;
        }
    }

    if (n != 0)
        ccnet_processor_send_update (processor, SC_BLOCKLIST, SS_BLOCKLIST,
                                     (char *)buf, len);
}

static int
process_block_bitmap (CcnetProcessor *processor, char *content, int clen)
{
    SeafileUploadBlockProc *proc = (SeafileUploadBlockProc *)processor;
    USE_PRIV;

    if (proc->block_bitmap.byteCount < priv->bm_offset + clen) {
        seaf_warning ("Received block bitmap is too large.\n");
        ccnet_processor_done (processor, FALSE);
        return -1;
    }
    memcpy (proc->block_bitmap.bits + priv->bm_offset, content, clen);

    priv->bm_offset += clen;
    if (priv->bm_offset == proc->block_bitmap.byteCount) {
        /* Update global uploaded bitmap. */
        BitfieldOr (&proc->task->uploaded, &proc->block_bitmap);
        proc->task->n_uploaded = BitfieldCountTrueBits (&proc->task->uploaded);
        ccnet_processor_send_update (processor, SC_GET_PORT, SS_GET_PORT,
                                     NULL, 0);
        processor->state = GET_PORT;
    }

    return 0;
}

static void* do_transfer(void *vtdata)
{
    ThreadData *tdata = vtdata;

    struct sockaddr_storage addr;
    struct sockaddr *sa  = (struct sockaddr*) &addr;
    socklen_t sa_len = sizeof (addr);
    evutil_socket_t data_fd;

    CcnetPeer *peer = tdata->peer;

    if (peer->addr_str == NULL) {
        seaf_warning ("peer address is NULL\n");
        tdata->thread_ret = -1;
        goto out;
    }

    if (sock_pton(peer->addr_str, tdata->port, &addr) < 0) {
        seaf_warning ("wrong address format %s\n", peer->addr_str);
        tdata->thread_ret = -1;
        goto out;
    }

    if ((data_fd = socket(sa->sa_family, SOCK_STREAM, 0)) < 0) {
        seaf_warning ("socket error: %s\n", strerror(errno));
        tdata->thread_ret = -1;
        goto out;
    }

#ifdef __APPLE__
    if (sa->sa_family == AF_INET)
        sa_len = sizeof(struct sockaddr_in);
    else if (sa->sa_family == PF_INET6)
        sa_len = sizeof(struct sockaddr_in6);
#endif

    if (connect(data_fd, sa, sa_len) < 0) {
        seaf_warning ("connect error: %s\n", strerror(errno));
        evutil_closesocket (data_fd);
        tdata->thread_ret = -1;
        goto out;
    }

    int token_len = strlen(tdata->token) + 1;
    if (sendn (data_fd, tdata->token, token_len) != token_len) {
        seaf_warning ("send connection token error: %s\n", strerror(errno));
        evutil_closesocket (data_fd);
        tdata->thread_ret = -1;
        goto out;
    }

    tdata->data_fd = data_fd;
    tdata->processor->state = ESTABLISHED;

    tdata->thread_ret = tdata->transfer_func(tdata);

    evutil_closesocket (tdata->data_fd);

out:
    pipeclose (tdata->task_pipe[0]);
    g_object_unref (peer);

    return vtdata;
}

static void
thread_done (void *vtdata)
{
    ThreadData *tdata = vtdata;

    /* When the worker thread returns, the processor may have been
     * released. tdata->processor_done will be set to TRUE in
     * release_resource().
     *
     * Note: thread_done() and release_thread() are both called
     * in main thread, so there are only two cases:
     * 1) thread_done() is called before release_resource(), then release_thread()
     *    is called within thread_done()
     * 2) release_thread() is called before thread_done(), then tdata->processor_done
     *    is set.
     */
    if (!tdata->processor_done) {
        seaf_debug ("Processor is not released. Release it now.\n");
        if (tdata->thread_ret == 0)
            ccnet_processor_done (tdata->processor, TRUE);
        else
            ccnet_processor_done (tdata->processor, FALSE);
    }

    g_free (tdata->token);
    g_free (tdata);
}

static void
get_port (CcnetProcessor *processor, char *content, int clen)
{
    USE_PRIV;
    ThreadData *tdata = priv->tdata;
    char *p, *port_str, *token;

    if (content[clen-1] != '\0') {
        seaf_warning ("Bad port and token\n");
        ccnet_processor_done (processor, FALSE);
        return;
    }

    p = strchr (content, '\t');
    if (!p) {
        seaf_warning ("Bad port and token\n");
        ccnet_processor_done (processor, FALSE);
        return;
    }

    *p = '\0';
    port_str = content; token = p + 1;

    CcnetPeer *peer = ccnet_get_peer (seaf->ccnetrpc_client, processor->peer_id);
    if (!peer) {
        seaf_warning ("Invalid peer %s.\n", processor->peer_id);
        g_free (tdata);
        ccnet_processor_done (processor, FALSE);
        return;
    }
    /* Store peer address so that we don't need to call ccnet_get_peer()
     * in the worker thread later.
     */
    if (ccnet_pipe (tdata->task_pipe) < 0) {
        seaf_warning ("failed to create task pipe.\n");
        g_free (tdata);
        ccnet_processor_done (processor, FALSE);
        return;
    }
    
    tdata->port = atoi (port_str);
    tdata->token = g_strdup(token);
    tdata->peer = peer;

    ccnet_job_manager_schedule_job (seaf->job_mgr,
                                    do_transfer,
                                    thread_done,
                                    tdata);
}

static void
process_ack (CcnetProcessor *processor, char *content, int clen)
{
    SeafileUploadBlockProc *proc = (SeafileUploadBlockProc *)processor;
    int block_idx;

    if (content[clen-1] != '\0') {
        g_warning ("Bad block ack.\n");
        ccnet_processor_done (processor, FALSE);
        return;
    }

    block_idx = atoi(content);
    if (block_idx < 0 || block_idx >= proc->task->block_list->n_blocks) {
        g_warning ("Bad block index %d.\n", block_idx);
        ccnet_processor_done (processor, FALSE);
        return;
    }

    BitfieldRem (&proc->active, block_idx);
    BitfieldRem (&proc->task->active, block_idx);
    BitfieldAdd (&proc->task->uploaded, block_idx);
    g_debug ("[sendlbock] recv ack for block %d\n", block_idx);
    ++(proc->task->n_uploaded);
}

static void
handle_response (CcnetProcessor *processor,
                 char *code, char *code_msg,
                 char *content, int clen)
{
    SeafileUploadBlockProc *proc = (SeafileUploadBlockProc *)processor;

    if (proc->task->state != UPLOAD_TASK_STATE_NORMAL) {
        g_debug("Task not runnimg, uploadblock proc exits.\n");
        ccnet_processor_done(processor, TRUE);
        return;
    }

    switch (processor->state) {
    case REQUEST_SENT:
        if (memcmp (code, SC_OK, 3) == 0) {
            send_block_list (processor);
            processor->state = BLOCKLIST_SENT;
            return;
        }
        break;
    case BLOCKLIST_SENT:
        if (memcmp (code, SC_BBITMAP, 3) == 0) {
            process_block_bitmap (processor, content, clen);
            return;
        }
        break;
    case GET_PORT:
        if (memcmp (code, SC_SEND_PORT, 3) == 0) {
            get_port (processor, content, clen);
            return;
        }
        break;
    case ESTABLISHED:
        if (memcmp (code, SC_ACK, 3) == 0) {
            process_ack (processor, content, clen);
            return;
        }
        break;
    }

    g_warning ("Bad response: %s %s.\n", code, code_msg);
    if (memcmp (code, SC_ACCESS_DENIED, 3) == 0)
        upload_task_set_error (proc->task, UPLOAD_TASK_ERR_ACCESS_DENIED);
    ccnet_processor_done (processor, FALSE);
}

int
seafile_upload_block_proc_send_block (SeafileUploadBlockProc *proc, int block_idx)
{
    CcnetProcessor *processor = (CcnetProcessor *)proc;
    BlockList *bl = proc->task->block_list;
    char *block_id;
    USE_PRIV;

    if (processor->state != ESTABLISHED)
        return -1;

    if (block_idx < 0 || block_idx >= bl->n_blocks)
        return -1;
    block_id = g_ptr_array_index (bl->block_ids, block_idx);

    BlockRequest blk_req;
    memcpy (blk_req.block_id, block_id, 41);
    blk_req.block_idx = block_idx;
    if (pipewriten (priv->tdata->task_pipe[1], 
                    &blk_req, sizeof(blk_req)) < 0) {
        g_warning ("failed to write task pipe.\n");
        return -1;
    }

    ++(proc->pending_blocks);
    BitfieldAdd (&proc->active, block_idx);

    return 0;
}

gboolean
seafile_upload_block_proc_is_ready (SeafileUploadBlockProc *proc)
{
    return (((CcnetProcessor *)proc)->state == ESTABLISHED);
}

