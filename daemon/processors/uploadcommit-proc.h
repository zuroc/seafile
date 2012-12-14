/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef SEAFILE_UPLOAD_COMMIT_PROC_H
#define SEAFILE_UPLOAD_COMMIT_PROC_H

#include <glib-object.h>


#define SEAFILE_TYPE_UPLOAD_COMMIT_PROC                  (seafile_upload_commit_proc_get_type ())
#define SEAFILE_UPLOAD_COMMIT_PROC(obj)                  (G_TYPE_CHECK_INSTANCE_CAST ((obj), SEAFILE_TYPE_UPLOAD_COMMIT_PROC, SeafileUploadCommitProc))
#define SEAFILE_IS_UPLOAD_COMMIT_PROC(obj)               (G_TYPE_CHECK_INSTANCE_TYPE ((obj), SEAFILE_TYPE_UPLOAD_COMMIT_PROC))
#define SEAFILE_UPLOAD_COMMIT_PROC_CLASS(klass)          (G_TYPE_CHECK_CLASS_CAST ((klass), SEAFILE_TYPE_UPLOAD_COMMIT_PROC, SeafileUploadCommitProcClass))
#define IS_SEAFILE_UPLOAD_COMMIT_PROC_CLASS(klass)       (G_TYPE_CHECK_CLASS_TYPE ((klass), SEAFILE_TYPE_UPLOAD_COMMIT_PROC))
#define SEAFILE_UPLOAD_COMMIT_PROC_GET_CLASS(obj)        (G_TYPE_INSTANCE_GET_CLASS ((obj), SEAFILE_TYPE_UPLOAD_COMMIT_PROC, SeafileUploadCommitProcClass))

typedef struct _SeafileUploadCommitProc SeafileUploadCommitProc;
typedef struct _SeafileUploadCommitProcClass SeafileUploadCommitProcClass;

struct _SeafileUploadCommitProc {
    CcnetProcessor parent_instance;

    UploadTask  *task;
};

struct _SeafileUploadCommitProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_upload_commit_proc_get_type ();

#endif
