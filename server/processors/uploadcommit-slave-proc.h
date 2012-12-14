/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_UPLOAD_COMMIT_SLAVE_PROC_H
#define SEAFILE_UPLOAD_COMMIT_SLAVE_PROC_H

#include <glib-object.h>


#define SEAFILE_TYPE_UPLOAD_COMMIT_SLAVE_PROC                  (seafile_upload_commit_slave_proc_get_type ())
#define SEAFILE_UPLOAD_COMMIT_SLAVE_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_UPLOAD_COMMIT_SLAVE_PROC, SeafileUploadCommitSlaveProc))
#define SEAFILE_IS_UPLOAD_COMMIT_SLAVE_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_UPLOAD_COMMIT_SLAVE_PROC))
#define SEAFILE_UPLOAD_COMMIT_SLAVE_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_UPLOAD_COMMIT_SLAVE_PROC, SeafileUploadCommitSlaveProcClass))
#define IS_SEAFILE_UPLOAD_COMMIT_SLAVE_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_UPLOAD_COMMIT_SLAVE_PROC))
#define SEAFILE_UPLOAD_COMMIT_SLAVE_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_UPLOAD_COMMIT_SLAVE_PROC, SeafileUploadCommitSlaveProcClass))

typedef struct _SeafileUploadCommitSlaveProc SeafileUploadCommitSlaveProc;
typedef struct _SeafileUploadCommitSlaveProcClass SeafileUploadCommitSlaveProcClass;

struct _SeafileUploadCommitSlaveProc {
    CcnetProcessor parent_instance;
};

struct _SeafileUploadCommitSlaveProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_upload_commit_slave_proc_get_type ();

#endif
