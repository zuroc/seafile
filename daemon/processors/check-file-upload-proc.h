#ifndef SEAFILE_CHECK_FILE_UPLOAD_PROC_H
#define SEAFILE_CHECK_FILE_UPLOAD_PROC_H

#include <glib-object.h>
#include <ccnet/processor.h>

#include "file-upload-mgr.h"

#define SEAFILE_TYPE_CHECK_FILE_UPLOAD_PROC             (seafile_check_file_upload_proc_get_type())
#define SEAFILE_CHECK_FILE_UPLOAD_PROC(obj)             (G_TYPE_CHECK_INSTANCE_CAST((obj), SEAFILE_TYPE_CHECK_FILE_UPLOAD_PROC, SeafileCheckFileUploadProc))
#define SEAFILE_IS_CHECK_FILE_UPLOAD_PROC(obj)          (G_TYPE_CHECK_INSTANCE_TYPE((obj), SEAFILE_TYPE_CHECK_FILE_UPLOAD_PROC))
#define SEAFILE_CHECK_FILE_UPLOAD_PROC_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST((klass), SEAFILE_TYPE_CHECK_FILE_UPLOAD_PROC, SeafileCheckFileUploadProcClass))
#define IS_SEAFILE_CHECK_FILE_UPLOAD_PROC_CLASS(klass)  (G_TYPE_CEHCK_CLASS_TYPE((klass), SEAFILE_TYPE_CHECK_FILE_UPLOAD_PROC))
#define SEAFILE_CHECK_FILE_UPLOAD_PROC_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS((obj), SEAFILE_TYPE_CHECK_FILE_UPLOAD_PROC, SeafileCheckFileUploadProcClass))

typedef struct _SeafileCheckFileUploadProc SeafileCheckFileUploadProc;
typedef struct _SeafileCheckFileUploadProcClass SeafileCheckFileUploadProcClass;

struct _SeafileCheckFileUploadProc {
    CcnetProcessor parent_instance;

    UploadTask *task;
};

struct _SeafileCheckFileUploadProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_check_file_upload_proc_get_type();

#endif /* SEAFILE_CHECK_FILE_UPLOAD_PROC_H */
