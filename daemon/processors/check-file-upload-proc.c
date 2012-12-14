#include <string.h>

#include <ccnet.h>

#include "common.h"
#include "seafile-session.h"
#include "vc-common.h"
#include "seafile-crypt.h"
#include "log.h"
#include "utils.h"

#include "check-file-upload-proc.h"

#define SC_GET_TOKEN        "301"
#define SS_GET_TOKEN        "Get token"
#define SC_PUT_TOKEN        "302"
#define SS_PUT_TOKEN        "Put token"

G_DEFINE_TYPE(SeafileCheckFileUploadProc, seafile_check_file_upload_proc, CCNET_TYPE_PROCESSOR)

static int start (CcnetProcessor *processor, int argc, char **argv);
static void handle_response (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen);
static char *encrypt_token (CcnetProcessor *processor, const char *token);

static void
release_resource(CcnetProcessor *processor)
{
    CCNET_PROCESSOR_CLASS (seafile_check_file_upload_proc_parent_class)->release_resource (processor);
}

static void seafile_check_file_upload_proc_class_init(SeafileCheckFileUploadProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS(klass);

    proc_class->name = "check-file-upload-proc";
    proc_class->start = start;
    proc_class->handle_response = handle_response;
    proc_class->release_resource = release_resource;
}

static void
seafile_check_file_upload_proc_init(SeafileCheckFileUploadProc *processor)
{
}

/* token -> AES encrypt with session key -> rawdata_to_hex -> output  */
static char *
encrypt_token (CcnetProcessor *processor, const char *token)
{
    CcnetPeer *peer = NULL;
    char *enc_out = NULL;
    SeafileCrypt *crypt = NULL;
    unsigned char key[16], iv[16];
    int len;
    char *output = NULL;

    if (!token)
        goto out;

    peer = ccnet_get_peer(seaf->ccnetrpc_client, processor->peer_id);
    if (!peer || !peer->session_key) {
        seaf_warning ("[check file upload] peer or peer session key not exist\n");
        goto out;
    }

    seafile_generate_enc_key (peer->session_key,
                              strlen(peer->session_key),
                              CURRENT_ENC_VERSION, key, iv);
                              
    crypt = seafile_crypt_new (CURRENT_ENC_VERSION, key, iv);
    
    /* encrypt the token with session key, including the trailing null byte */
    if (seafile_encrypt (&enc_out, &len, token, strlen(token) + 1, crypt) < 0) {
        seaf_warning ("[check file upload] failed to encrypt token\n");
        goto out;
    }

    output = g_malloc (len * 2 + 1);
    rawdata_to_hex ((unsigned char *)enc_out, output, len);
    output[len * 2] = '\0';

    
out:
    g_free (crypt);
    g_free (enc_out);
    if (peer)
        g_object_unref(peer);

    return output;
}

static int
start (CcnetProcessor *processor, int argc, char **argv)
{
    SeafileCheckFileUploadProc *proc = (SeafileCheckFileUploadProc *)processor;
    UploadTask *task = proc->task;
    char *enc_token;
    GString *buf;

    enc_token = encrypt_token(processor, task->token);
    if (!enc_token) {
        transition_state_to_error(task, UPLOAD_TASK_ERR_CHECK_UPLOAD_START);
        ccnet_processor_done(processor, FALSE);
        return -1;
    }

    buf = g_string_new(NULL);
    g_string_append_printf(buf,
            "remote %s seafile-check-file-upload-slave-proc %s %s %s",
            processor->peer_id, task->repo_id, task->topath, enc_token);

    ccnet_processor_send_request(processor, buf->str);

    g_free(enc_token);
    g_string_free(buf, TRUE);

    return 0;
}

static void
handle_response (CcnetProcessor *processor,
                 char *code, char *code_msg,
                 char *content, int clen)
{
    SeafileCheckFileUploadProc *proc = (SeafileCheckFileUploadProc *)processor;
    UploadTask *task = proc->task;

    if (strncmp(code, SC_OK, 3) == 0) {
        if (clen == 0) {
            ccnet_processor_send_update(processor,
                                        SC_GET_TOKEN, SS_GET_TOKEN,
                                        NULL, 0);
            return;
        } else {
            g_warning("Bad response content.\n");
            upload_task_set_error(task, UPLOAD_TASK_ERR_UNKNOWN);
            ccnet_processor_done(processor, FALSE);
            return;
        }
    } else if (strncmp(code, SC_PUT_TOKEN, 3) == 0) {
#if 0
        /* In LAN sync, we don't use session token. */
        if (clen == 0) {
            ccnet_processor_done (processor, TRUE);
            return;
        }
#endif
        if (content[clen-1] != '\0') {
            g_warning("Bad response content.\n");
            upload_task_set_error(task, UPLOAD_TASK_ERR_UNKNOWN);
            ccnet_processor_done(processor, FALSE);
            return;
        }

        task->session_token = g_strdup (content);
        ccnet_processor_done (processor, TRUE);
    } else {
        g_warning("[chec file upload] Bad response: %s %s", code, code_msg);
        ccnet_processor_done (processor, FALSE);
    }
}
