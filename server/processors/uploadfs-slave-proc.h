#ifndef SEAFILE_UPLOADFS_SLAVE_PROC_H
#define SEAFILE_UPLOADFS_SLAVE_PROC_H

#include <glib-object.h>
#include <ccnet/processor.h>

#define SEAFILE_TYPE_UPLOADFS_SLAVE_PROC             (seafile_uploadfs_slave_proc_get_type())
#define SEAFILE_UPLOADFS_SLAVE_PROC(obj)             (G_TYPE_CHECK_INSTANCE_CAST((obj), SEAFILE_TYPE_UPLOADFS_SLAVE_PROC, SeafileUploadfsSlaveProc))
#define SEAFILE_IS_UPLOADFS_SLAVE_PROC(obj)          (G_TYPE_CHECK_INSTANCE_TYPE((obj), SEAFILE_TYPE_UPLOADFS_SLAVE_PROC))
#define SEAFILE_UPLOADFS_SLAVE_PROC_CLASS(klass)     (G_TYPE_CHECK_CLASS_CAST((klass), SEAFILE_TYPE_UPLOADFS_SLAVE_PROC, SeafileUploadfsSlaveProcClass))
#define IS_SEAFILE_UPLOADFS_SLAVE_PROC_CLASS(klass)  (G_TYPE_CEHCK_CLASS_TYPE((klass), SEAFILE_TYPE_UPLOADFS_SLAVE_PROC))
#define SEAFILE_UPLOADFS_SLAVE_PROC_GET_CLASS(obj)   (G_TYPE_INSTANCE_GET_CLASS((obj), SEAFILE_TYPE_UPLOADFS_SLAVE_PROC, SeafileUploadfsSlaveProcClass))

typedef struct _SeafileUploadfsSlaveProc SeafileUploadfsSlaveProc;
typedef struct _SeafileUploadfsSlaveProcClass SeafileUploadfsSlaveProcClass;

struct _SeafileUploadfsSlaveProc {
    CcnetProcessor parent_instance;
};

struct _SeafileUploadfsSlaveProcClass {
    CcnetProcessorClass parent_class;
};

GType seafile_uploadfs_slave_proc_get_type();

#endif /* SEAFILE_UPLOADFS_SLAVE_PROC_H */
