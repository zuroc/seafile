#ifndef SEAFILE_CHECK_FILE_UPLOAD_SLAVE_PROC_H
#define SEAFILE_CHECK_FILE_UPLOAD_SLAVE_PROC_H

#include <glib-object.h>
#include <ccnet/processor.h>

#define SEAFILE_TYPE_CHECK_FILE_UPLOAD_SLAVE_PROC             (seafile_check_file_upload_slave_proc_get_type())
#define SEAFILE_CHECK_FILE_UPLOAD_SLAVE_PROC(obj)             (G_TYPE_CHECK_INSTANCE_CAST((obj), SEAFILE_TYPE_CHECK_FILE_UPLOAD_SLAVE_PROC, SeafileCheckFileUploadSlaveProc))
#define SEAFILE_IS_CHECK_FILE_UPLOAD_SLAVE_PROC(obj)          (G_TYPE_CHECK_INSTANCE_TYPE((obj), SEAFILE_TYPE_CHECK_FILE_UPLOAD_SLAVE_PROC))
#define SEAFILE_CHECK_FILE_UPLOAD_SLAVE_PROC_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST((klass), SEAFILE_TYPE_CHECK_FILE_UPLOAD_SLAVE_PROC, SeafileCheckFileUploadSlaveProcClass))
#define IS_SEAFILE_CHECK_FILE_UPLOAD_SLAVE_PROC_CLASS(klass)  (G_TYPE_CEHCK_CLASS_TYPE((klass), SEAFILE_TYPE_CHECK_FILE_UPLOAD_SLAVE_PROC))
#define SEAFILE_CHECK_FILE_UPLOAD_SLAVE_PROC_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS((obj), SEAFILE_TYPE_CHECK_FILE_UPLOAD_SLAVE_PROC, SeafileCheckFileUploadSlaveProcClass))

typedef struct _SeafileCheckFileUploadSlaveProc SeafileCheckFileUploadSlaveProc;
typedef struct _SeafileCheckFileUploadSlaveProcClass SeafileCheckFileUploadSlaveProcClass;

struct _SeafileCheckFileUploadSlaveProc {
    CcnetProcessor parent_instance;
};

struct _SeafileCheckFileUploadSlaveProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_check_file_upload_slave_proc_get_type();

#endif /* SEAFILE_CHECK_FILE_UPLOAD_SLAVE_PROC_H */
