#ifndef SEAFILE_UPLOAD_BLOCK_PROC_H
#define SEAFILE_UPLOAD_BLOCK_PROC_H

#include <glib-object.h>
#include <ccnet/processor.h>

#include "file-upload-mgr.h"

#define SEAFILE_TYPE_UPLOAD_BLOCK_PROC             (seafile_upload_block_proc_get_type())
#define SEAFILE_UPLOAD_BLOCK_PROC(obj)             (G_TYPE_CHECK_INSTANCE_CAST((obj), SEAFILE_TYPE_UPLOAD_BLOCK_PROC, SeafileUploadBlockProc))
#define SEAFILE_IS_UPLOAD_BLOCK_PROC(obj)          (G_TYPE_CHECK_INSTANCE_TYPE((obj), SEAFILE_TYPE_UPLOAD_BLOCK_PROC))
#define SEAFILE_UPLOAD_BLOCK_PROC_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST((klass), SEAFILE_TYPE_UPLOAD_BLOCK_PROC, SeafileUploadBlockProcClass))
#define IS_SEAFILE_UPLOAD_BLOCK_PROC_CLASS(klass)  (G_TYPE_CEHCK_CLASS_TYPE((klass), SEAFILE_TYPE_UPLOAD_BLOCK_PROC))
#define SEAFILE_UPLOAD_BLOCK_PROC_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS((obj), SEAFILE_TYPE_UPLOAD_BLOCK_PROC, SeafileUploadBlockProcClass))

typedef struct _SeafileUploadBlockProc SeafileUploadBlockProc;
typedef struct _SeafileUploadBlockProcClass SeafileUploadBlockProcClass;

struct _SeafileUploadBlockProc {
    CcnetProcessor parent_instance;

    UploadTask *task;
    Bitfield active;
    Bitfield block_bitmap;

    int            tx_bytes;
    int            tx_time;
    double         avg_tx_rate;
    int            pending_blocks;
};

#define MAX_BL_LEN 1024

typedef struct {
    int      block_idx;
    int      tx_bytes;
    int      tx_time;
} BlockResponse;

typedef struct {
    int     block_idx;
    char    block_id[41];
} BlockRequest;

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
    UploadTask          *task;
    uint32_t             cevent_id;
    ccnet_pipe_t         task_pipe[2];
    int                  port;
    evutil_socket_t      data_fd;

    gboolean             processor_done;
    char                *token;
    TransferFunc         transfer_func;
    int                  thread_ret;
};

struct _SeafileUploadBlockProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_upload_block_proc_get_type();

int seafile_upload_block_proc_send_block (SeafileUploadBlockProc *proc,
                                          int block_idx);

gboolean seafile_upload_block_proc_is_ready (SeafileUploadBlockProc *proc);

#endif /* SEAFILE_UPLOAD_BLOCK_PROC_H */
