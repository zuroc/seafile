#ifndef SEAFILE_COMMIT_UPLOAD_FILE_SLAVE_PROC_H
#define SEAFILE_COMMIT_UPLOAD_FILE_SLAVE_PROC_H

#include <glib-object.h>
#include <ccnet/processor.h>

#define SEAFILE_TYPE_COMMIT_UPLOAD_FILE_SLAVE_PROC             (seafile_commit_upload_file_slave_proc_get_type())
#define SEAFILE_COMMIT_UPLOAD_FILE_SLAVE_PROC(obj)             (G_TYPE_CHECK_INSTANCE_CAST((obj), SEAFILE_TYPE_COMMIT_UPLOAD_FILE_SLAVE_PROC, SeafileCommitUploadFileSlaveProc))
#define SEAFILE_IS_COMMIT_UPLOAD_FILE_SLAVE_PROC(obj)          (G_TYPE_CHECK_INSTANCE_TYPE((obj), SEAFILE_TYPE_COMMIT_UPLOAD_FILE_SLAVE_PROC))
#define SEAFILE_COMMIT_UPLOAD_FILE_SLAVE_PROC_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST((klass), SEAFILE_TYPE_COMMIT_UPLOAD_FILE_SLAVE_PROC, SeafileCommitUploadFileSlaveProcClass))
#define IS_SEAFILE_COMMIT_UPLOAD_FILE_SLAVE_PROC_CLASS(klass)  (G_TYPE_CEHCK_CLASS_TYPE((klass), SEAFILE_TYPE_COMMIT_UPLOAD_FILE_SLAVE_PROC))
#define SEAFILE_COMMIT_UPLOAD_FILE_SLAVE_PROC_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS((obj), SEAFILE_TYPE_COMMIT_UPLOAD_FILE_SLAVE_PROC, SeafileCommitUploadFileSlaveProcClass))

typedef struct _SeafileCommitUploadFileSlaveProc SeafileCommitUploadFileSlaveProc;
typedef struct _SeafileCommitUploadFileSlaveProcClass SeafileCommitUploadFileSlaveProcClass;

struct _SeafileCommitUploadFileSlaveProc {
    CcnetProcessor parent_instance;
};

struct _SeafileCommitUploadFileSlaveProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_commit_upload_file_slave_proc_get_type();

#endif /* SEAFILE_COMMIT_UPLOAD_FILE_SLAVE_PROC_H */
