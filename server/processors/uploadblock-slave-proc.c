/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

#include <ccnet.h>
#include <ccnet/cevent.h>
#include "net.h"
#include "utils.h"
#define DEBUG_FLAG SEAFILE_DEBUG_TRANSFER
#include "log.h"

#include "seafile-session.h"
#include "fs-mgr.h"
#include "block-mgr.h"
#include "uploadblock-slave-proc.h"

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

#define SC_ACCESS_DENIED    "401"
#define SS_ACCESS_DENIED    "Access Denied"

enum {
    PREPARE,
    ESTABLISHED,
};

#define GET_PRIV(o)  \
   (G_TYPE_INSTANCE_GET_PRIVATE ((o), SEAFILE_TYPE_UPLOAD_BLOCK_SLAVE_PROC, UploadBlockSlaveProcPriv))

#define USE_PRIV \
    UploadBlockSlaveProcPriv *priv = GET_PRIV(processor);

static int start (CcnetProcessor *processor, int argc, char **argv);
static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen);
static void release_resource (CcnetProcessor *processor);

G_DEFINE_TYPE (SeafileUploadBlockSlaveProc, seafile_upload_block_slave_proc, CCNET_TYPE_PROCESSOR)

static void
seafile_upload_block_slave_proc_class_init (SeafileUploadBlockSlaveProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "uploadblock-slave-proc";
    proc_class->start = start;
    proc_class->handle_update = handle_update;
    proc_class->release_resource = release_resource;

    g_type_class_add_private (klass, sizeof (UploadBlockSlaveProcPriv));
}

static void
seafile_upload_block_slave_proc_init (SeafileUploadBlockSlaveProc *processor)
{
}

static int
verify_session_token (CcnetProcessor *processor, int argc, char **argv)
{
    if (argc != 1) {
        return -1;
    }

    char *session_token = argv[0];
    if (seaf_token_manager_verify_token (seaf->token_mgr,
                                         processor->peer_id,
                                         session_token, NULL) < 0) {
        return -1;
    }

    return 0;
}

static int
recv_tick (RecvFSM *fsm, evutil_socket_t sockfd)
{
    SeafBlockManager *block_mgr = seaf->block_mgr;
    char *block_id;
    BlockHandle *handle;
    int n, round;
    char buf[1024];

    switch (fsm->state) {
    case RECV_STATE_HEADER:
        n = recv (sockfd, 
                  (char *)&fsm->hdr + sizeof(BlockPacket) - fsm->remain, 
                  fsm->remain, 0);
        if (n < 0) {
            seaf_warning ("Failed to read block pkt: %s.\n",
                       evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
            return -1;
        } else if (n == 0) {
            seaf_debug ("data connection closed.\n");
            return -1;
        }

        fsm->remain -= n;
        if (fsm->remain == 0) {
            fsm->remain = (int) ntohl (fsm->hdr.block_size);
            block_id = fsm->hdr.block_id;
            block_id[40] = 0;

            handle = seaf_block_manager_open_block (block_mgr, 
                                                    block_id, BLOCK_WRITE);
            if (!handle) {
                seaf_warning ("failed to open block %s.\n", block_id);
                return -1;
            }
            fsm->handle = handle; 
            fsm->state = RECV_STATE_BLOCK;
        }
        break;
    case RECV_STATE_BLOCK:
        handle = fsm->handle;
        block_id = fsm->hdr.block_id;

        round = MIN (fsm->remain, 1024);
        n = recv (sockfd, buf, round, 0);
        if (n < 0) {
            seaf_warning ("failed to read data: %s.\n",
                       evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
            return -1;
        } else if (n == 0) {
            seaf_debug ("data connection closed.\n");
            return -1;
        }

        if (seaf_block_manager_write_block (block_mgr, handle, buf, n) < 0) {
            seaf_warning ("Failed to write block %s.\n", fsm->hdr.block_id);
            return -1;
        }

#ifdef GETBLOCK_PROC
        /* Update global transferred bytes. */
        g_atomic_int_add (&(fsm->tdata->task->tx_bytes), n);
#endif

        fsm->remain -= n;
        if (fsm->remain == 0) {
            if (seaf_block_manager_close_block (block_mgr, handle) < 0) {
                seaf_warning ("Failed to close block %s.\n", fsm->hdr.block_id);
                return -1;
            }

            if (seaf_block_manager_commit_block (block_mgr, handle) < 0) {
                seaf_warning ("Failed to commit block %s.\n", fsm->hdr.block_id);
                return -1;
            }

            seaf_block_manager_block_handle_free (block_mgr, handle);
            /* Set this handle to invalid. */
            fsm->handle = NULL;

#ifdef GETBLOCK_PROC
            /* Notify finish receiving this block. */
            send_block_rsp (fsm->cevent_id,
                            (int)ntohl (fsm->hdr.block_idx),
                            0, 0);
#endif

            /* Prepare for the next packet. */
            fsm->state = RECV_STATE_HEADER;
            fsm->remain = sizeof(BlockPacket);
        }
        break;
    }

    return 0;
}

static int
upload_blocks_slave (ThreadData *tdata)
{
    fd_set fds;
    int max_fd = MAX (tdata->task_pipe[0], tdata->data_fd);
    int rc;

    RecvFSM *fsm = g_new0 (RecvFSM, 1);
    fsm->remain = sizeof (BlockPacket);
    fsm->cevent_id = tdata->cevent_id;
    fsm->tdata = tdata;

    while (1) {
        FD_ZERO (&fds);
        FD_SET (tdata->task_pipe[0], &fds);
        FD_SET (tdata->data_fd, &fds);

        rc = select (max_fd + 1, &fds, NULL, NULL, NULL);
        if (rc < 0 && errno == EINTR) {
            continue;
        } else if (rc < 0) {
            seaf_warning ("select error: %s.\n", strerror(errno));
            goto error;
        }

        if (FD_ISSET (tdata->data_fd, &fds)) {
            if (recv_tick (fsm, tdata->data_fd) < 0) {
                goto error;
            }
        }

        if (FD_ISSET (tdata->task_pipe[0], &fds)) {
            /* task_pipe becomes readable only when the write end
             * is closed, in this case 0 is returned.
             * This means the processor was done.
             */
            char buf[1];
            int n = piperead (tdata->task_pipe[0], buf, sizeof(buf));
            g_assert (n == 0);
            seaf_debug ("Task pipe closed. Worker thread exits now.\n");
            goto error;
        }
    }

    g_free (fsm);
    return 0;

error:
    if (fsm->handle) {
        seaf_block_manager_close_block (seaf->block_mgr, fsm->handle);
        seaf_block_manager_block_handle_free (seaf->block_mgr, fsm->handle);
    }
    g_free (fsm);
    return -1;
}

static void
upload_blocks_slave_cb (CEvent *event, void *vprocessor)
{
    CcnetProcessor *processor = vprocessor;
    BlockResponse *blk_rsp = event->data;
    char buf[32];
    int len;

    len = snprintf (buf, 32, "%d", blk_rsp->block_idx);
    ccnet_processor_send_response (processor, SC_ACK, SS_ACK,
                                   buf, len + 1);

    g_free (blk_rsp);
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
    if (verify_session_token(processor, argc, argv) < 0) {
        ccnet_processor_send_response(processor,
                                      SC_ACCESS_DENIED, SS_ACCESS_DENIED,
                                      NULL, 0);
        ccnet_processor_done(processor, FALSE);
        return -1;
    }

    prepare_thread_data(processor, upload_blocks_slave, upload_blocks_slave_cb);
    ccnet_processor_send_response(processor, "200", "OK", NULL, 0);
    return 0;
}

static void
release_resource (CcnetProcessor *processor)
{
    CCNET_PROCESSOR_CLASS(seafile_upload_block_slave_proc_parent_class)->release_resource (processor);
}

static void
process_block_list (CcnetProcessor *processor, char *content, int clen)
{
    char *block_id;
    int n_blocks;
    Bitfield bitmap;
    int i;

    if (clen % 41 != 0) {
        seaf_warning ("Bad block list.\n");
        ccnet_processor_send_response (processor, SC_BAD_BL, SS_BAD_BL, NULL, 0);
        ccnet_processor_done (processor, FALSE);
        return;
    }

    n_blocks = clen/41;
    BitfieldConstruct (&bitmap, n_blocks);

    block_id = content;
    for (i = 0; i < n_blocks; ++i) {
        block_id[40] = '\0';
        if (seaf_block_manager_block_exists(seaf->block_mgr, block_id))
            BitfieldAdd (&bitmap, i);
        block_id += 41;
    }

    ccnet_processor_send_response (processor, SC_BBITMAP, SS_BBITMAP,
                                   (char *)(bitmap.bits), bitmap.byteCount);
    BitfieldDestruct (&bitmap);
}

static void* do_passive_transfer(void *vtdata)
{
    ThreadData *tdata = vtdata;

    tdata->thread_ret = tdata->transfer_func (tdata);
    
    pipeclose (tdata->task_pipe[0]);
    evutil_closesocket (tdata->data_fd);
    
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
accept_connection (evutil_socket_t connfd, void *vdata)
{
    ThreadData *tdata = vdata;
    CcnetProcessor *processor = tdata->processor;

    /* client error or timeout */
    if (connfd < 0)
        goto fail;

    tdata->data_fd = connfd;

    processor->state = ESTABLISHED;

    if (ccnet_pipe (tdata->task_pipe) < 0) {
        seaf_warning ("failed to create task pipe.\n");
        evutil_closesocket (tdata->data_fd);
        goto fail;
    }

    ccnet_job_manager_schedule_job (seaf->job_mgr,
                                    do_passive_transfer,
                                    thread_done,
                                    tdata);
    return;

fail:
    ccnet_processor_done (processor, FALSE);
    g_free (tdata);
}

static void
send_port (CcnetProcessor *processor)
{
    USE_PRIV;
    char buf[256];
    char *token = NULL;
    int len;

    token = seaf_listen_manager_generate_token (seaf->listen_mgr);
    if (seaf_listen_manager_register_token (seaf->listen_mgr, token,
                        (ConnAcceptedCB)accept_connection,
                        priv->tdata, 10) < 0) {
        seaf_warning ("failed to register token\n");
        g_free (token);
        ccnet_processor_done (processor, FALSE);
    }

    len = snprintf (buf, sizeof(buf), "%d\t%s", seaf->listen_mgr->port, token);
    ccnet_processor_send_response (processor,
                                   SC_SEND_PORT, SS_SEND_PORT,
                                   buf, len+1);

    g_free (token);
}

static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen)
{
    switch (processor->state) {
    case PREPARE:
        if (memcmp (code, SC_BLOCKLIST, 3) == 0) {
            process_block_list (processor, content, clen);
            return;
        } else if (memcmp (code, SC_GET_PORT, 3) == 0) {
            send_port (processor);
            return;
        }
        break;
        break;
    }

    g_warning ("Bad code: %s %s\n", code, code_msg);
    ccnet_processor_send_response (processor, SC_BAD_UPDATE_CODE, 
                                   SS_BAD_UPDATE_CODE, NULL, 0);
    ccnet_processor_done (processor, FALSE);
}
