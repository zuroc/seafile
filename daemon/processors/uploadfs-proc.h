#ifndef SEAFILE_UPLOADFS_PROC_H
#define SEAFILE_UPLOADFS_PROC_H

#include <glib-object.h>
#include <ccnet/processor.h>

#include "file-upload-mgr.h"

#define SEAFILE_TYPE_UPLOADFS_PROC             (seafile_uploadfs_proc_get_type())
#define SEAFILE_UPLOADFS_PROC(obj)             (G_TYPE_CHECK_INSTANCE_CAST((obj), SEAFILE_TYPE_UPLOADFS_PROC, SeafileUploadfsProc))
#define SEAFILE_IS_UPLOADFS_PROC(obj)          (G_TYPE_CHECK_INSTANCE_TYPE((obj), SEAFILE_TYPE_UPLOADFS_PROC))
#define SEAFILE_UPLOADFS_PROC_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST((klass), SEAFILE_TYPE_UPLOADFS_PROC, SeafileUploadfsProcClass))
#define IS_SEAFILE_UPLOADFS_PROC_CLASS(klass)  (G_TYPE_CEHCK_CLASS_TYPE((klass), SEAFILE_TYPE_UPLOADFS_PROC))
#define SEAFILE_UPLOADFS_PROC_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS((obj), SEAFILE_TYPE_UPLOADFS_PROC, SeafileUploadfsProcClass))

typedef struct _SeafileUploadfsProc SeafileUploadfsProc;
typedef struct _SeafileUploadfsProcClass SeafileUploadfsProcClass;

struct _SeafileUploadfsProc {
    CcnetProcessor parent_instance;

    UploadTask *task;
};

struct _SeafileUploadfsProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_uploadfs_proc_get_type();

#endif /* SEAFILE_UPLOADFS_PROC_H */
