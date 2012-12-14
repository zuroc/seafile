/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_UPLOAD_BLOCK_SLAVE_PROC_H
#define SEAFILE_UPLOAD_BLOCK_SLAVE_PROC_H

#include <glib-object.h>


#define SEAFILE_TYPE_UPLOAD_BLOCK_SLAVE_PROC                  (seafile_upload_block_slave_proc_get_type ())
#define SEAFILE_UPLOAD_BLOCK_SLAVE_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_UPLOAD_BLOCK_SLAVE_PROC, SeafileUploadBlockSlaveProc))
#define SEAFILE_IS_UPLOAD_BLOCK_SLAVE_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_UPLOAD_BLOCK_SLAVE_PROC))
#define SEAFILE_UPLOAD_BLOCK_SLAVE_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_UPLOAD_BLOCK_SLAVE_PROC, SeafileUploadBlockSlaveProcClass))
#define IS_SEAFILE_UPLOAD_BLOCK_SLAVE_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_UPLOAD_BLOCK_SLAVE_PROC))
#define SEAFILE_UPLOAD_BLOCK_SLAVE_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_UPLOAD_BLOCK_SLAVE_PROC, SeafileUploadBlockSlaveProcClass))

typedef struct _SeafileUploadBlockSlaveProc SeafileUploadBlockSlaveProc;
typedef struct _SeafileUploadBlockSlaveProcClass SeafileUploadBlockSlaveProcClass;

struct _SeafileUploadBlockSlaveProc {
    CcnetProcessor parent_instance;
};

struct _SeafileUploadBlockSlaveProcClass {
    CcnetProcessorClass parent_class;
};

typedef struct {
    int     block_idx;
    char    block_id[41];
} BlockRequest;

typedef struct {
    int      block_idx;
    int      tx_bytes;
    int      tx_time;
} BlockResponse;

typedef struct {
    uint32_t block_size;
    uint32_t block_idx;
    char     block_id[41];
} __attribute__((__packed__)) BlockPacket;

typedef struct ThreadData ThreadData;

/* function called when receiving event from transfer thread via pipe. */
typedef void (*ThreadEventHandler) (CEvent *event, void *vprocessor);
typedef int  (*TransferFunc) (ThreadData *tdata);

struct ThreadData {
    CcnetPeer           *peer;
    /* Never dereference this processor in the worker thread */
    CcnetProcessor      *processor;
    uint32_t             cevent_id;
    ccnet_pipe_t         task_pipe[2];
    int                  port;
    evutil_socket_t      data_fd;

    gboolean             processor_done;
    char                *token;
    TransferFunc         transfer_func;
    int                  thread_ret;
};

typedef struct {
    ThreadData      *tdata;
    int              bm_offset;
    GHashTable      *block_hash;
} UploadBlockSlaveProcPriv;

enum {
    RECV_STATE_HEADER,
    RECV_STATE_BLOCK,
};

typedef struct {
    ThreadData *tdata;
    int state;
    BlockPacket hdr;
    int remain;
    BlockHandle *handle;
    uint32_t cevent_id;
} RecvFSM;

GType seafile_upload_block_slave_proc_get_type ();

#endif /* SEAFILE_UPLOAD_BLOCK_SLAVE_PROC_GET_CLASS */
