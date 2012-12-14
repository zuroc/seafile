#ifndef SEAFILE_COMMIT_UPLOAD_FILE_PROC_H
#define SEAFILE_COMMIT_UPLOAD_FILE_PROC_H

#include <glib-object.h>
#include <ccnet/processor.h>

#include "file-upload-mgr.h"

#define SEAFILE_TYPE_COMMIT_UPLOAD_FILE_PROC             (seafile_commit_upload_file_proc_get_type())
#define SEAFILE_COMMIT_UPLOAD_FILE_PROC(obj)             (G_TYPE_CHECK_INSTANCE_CAST((obj), SEAFILE_TYPE_COMMIT_UPLOAD_FILE_PROC, SeafileCommitUploadFileProc))
#define SEAFILE_IS_COMMIT_UPLOAD_FILE_PROC(obj)          (G_TYPE_CHECK_INSTANCE_TYPE((obj), SEAFILE_TYPE_COMMIT_UPLOAD_FILE_PROC))
#define SEAFILE_COMMIT_UPLOAD_FILE_PROC_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST((klass), SEAFILE_TYPE_COMMIT_UPLOAD_FILE_PROC, SeafileCommitUploadFileProcClass))
#define IS_SEAFILE_COMMIT_UPLOAD_FILE_PROC_CLASS(klass)  (G_TYPE_CEHCK_CLASS_TYPE((klass), SEAFILE_TYPE_COMMIT_UPLOAD_FILE_PROC))
#define SEAFILE_COMMIT_UPLOAD_FILE_PROC_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS((obj), SEAFILE_TYPE_COMMIT_UPLOAD_FILE_PROC, SeafileCommitUploadFileProcClass))

typedef struct _SeafileCommitUploadFileProc SeafileCommitUploadFileProc;
typedef struct _SeafileCommitUploadFileProcClass SeafileCommitUploadFileProcClass;

struct _SeafileCommitUploadFileProc {
    CcnetProcessor parent_instance;

    UploadTask *task;
};

struct _SeafileCommitUploadFileProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_commit_upload_file_proc_get_type();

#endif /* SEAFILE_COMMIT_UPLOAD_FILE_PROC_H */
