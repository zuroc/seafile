/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"

#define DEBUG_FLAG SEAFILE_DEBUG_TRANSFER
#include "log.h"

#include <fcntl.h>

#include <ccnet.h>
#include "net.h"
#include "utils.h"

#include "seafile-session.h"
#include "uploadcommit-slave-proc.h"
#include "processors/objecttx-common.h"
#include "seaf-utils.h"

#define SC_COMMIT   "301"
#define SS_COMMIT   "Send Commit"
#define SC_DONE     "302"
#define SS_DONE     "Done"

static int start (CcnetProcessor *processor, int argc, char **argv);
static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen);


G_DEFINE_TYPE (SeafileUploadCommitSlaveProc, seafile_upload_commit_slave_proc, CCNET_TYPE_PROCESSOR)

static void
release_resource (CcnetProcessor *processor)
{
}

static void
seafile_upload_commit_slave_proc_class_init (SeafileUploadCommitSlaveProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS (klass);

    proc_class->name = "uploadcommit-slave-proc";
    proc_class->start = start;
    proc_class->handle_update = handle_update;
    proc_class->release_resource = release_resource;
}

static void
seafile_upload_commit_slave_proc_init (SeafileUploadCommitSlaveProc *processor)
{
}

static int
start (CcnetProcessor *processor, int argc, char **argv)
{
    char *session_token;

    if (argc != 1) {
        ccnet_processor_send_response(processor, SC_BAD_ARGS, SS_BAD_ARGS, NULL, 0);
        ccnet_processor_done(processor, FALSE);
        return -1;
    }

    session_token = argv[0];

    if (seaf_token_manager_verify_token(seaf->token_mgr,
                                        processor->peer_id,
                                        session_token, NULL) == 0) {
        ccnet_processor_send_response(processor, SC_OK, SS_OK, NULL, 0);
        return 0;
    } else {
        ccnet_processor_send_response(processor,
                                      SC_ACCESS_DENIED, SS_ACCESS_DENIED,
                                      NULL, 0);
        ccnet_processor_done(processor, FALSE);
        return -1;
    }
}

static int recv_commit(CcnetProcessor *processor, char *content, int clen)
{
    ObjectPack *pack = (ObjectPack *)content;

    if (clen < sizeof(ObjectPack))
        return -1;

    if (seaf_obj_store_write_obj(seaf->commit_mgr->obj_store,
                                 pack->id,
                                 pack->object,
                                 clen - 41) < 0)
        return -1;

    return 0;
}

static void handle_update (CcnetProcessor *processor,
                           char *code, char *code_msg,
                           char *content, int clen)
{
    if (strncmp(code, SC_COMMIT, 3) == 0) {
        if (recv_commit(processor, content, clen) < 0) {
            ccnet_processor_send_response(processor,
                                          SC_BAD_ARGS, SS_BAD_ARGS, NULL, 0);
            ccnet_processor_done(processor, FALSE);
            return;
        }
        ccnet_processor_send_response(processor, SC_DONE, SS_DONE, NULL, 0);
        ccnet_processor_done(processor, TRUE);
        return;
    }

    ccnet_processor_send_response(processor, SC_BAD_ARGS, SS_BAD_ARGS, NULL, 0);
    ccnet_processor_done(processor, FALSE);
}
