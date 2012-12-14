#include <string.h>

#include <ccnet.h>

#include "common.h"
#include "seafile-session.h"
#include "vc-common.h"
#include "seafile-crypt.h"
#include "utils.h"

#define DEBUG_FLAG SEAFILE_DEBUG_TRANSFER
#include "log.h"

#include "check-file-upload-slave-proc.h"

#define SC_GET_TOKEN        "301"
#define SS_GET_TOKEN        "Get token"
#define SC_PUT_TOKEN        "302"
#define SS_PUT_TOKEN        "Put token"

#define SC_ACCESS_DENIED    "401"
#define SS_ACCESS_DENIED    "Access denied"
#define SC_BAD_REPO         "406"
#define SS_BAD_REPO         "Repo doesn't exist"

enum {
    INIT,
    ACCESS_GRANTED,
};

G_DEFINE_TYPE(SeafileCheckFileUploadSlaveProc, seafile_check_file_upload_slave_proc, CCNET_TYPE_PROCESSOR)

typedef struct {
    char repo_id[37];
    char *token;
    char *session_key;
    char *rsp_code;
    char *rsp_msg;
} SeafileCheckFileUploadSlaveProcPriv;

#define GET_PRIV(o) \
    (G_TYPE_INSTANCE_GET_PRIVATE ((o), SEAFILE_TYPE_CHECK_FILE_UPLOAD_SLAVE_PROC, SeafileCheckFileUploadSlaveProcPriv))

#define USE_PRIV \
    SeafileCheckFileUploadSlaveProcPriv *priv = GET_PRIV(processor)

static int start (CcnetProcessor *processor, int argc, char **argv);
static void handle_update (CcnetProcessor *processor,
                             char *code, char *code_msg,
                             char *content, int clen);
static int decrypt_token(CcnetProcessor *processor);

static void
release_resource(CcnetProcessor *processor)
{
    USE_PRIV;

    g_free(priv->token);
    g_free(priv->session_key);
    g_free(priv->rsp_code);
    g_free(priv->rsp_msg);

    CCNET_PROCESSOR_CLASS (seafile_check_file_upload_slave_proc_parent_class)->release_resource (processor);
}

static void seafile_check_file_upload_slave_proc_class_init(SeafileCheckFileUploadSlaveProcClass *klass)
{
    CcnetProcessorClass *proc_class = CCNET_PROCESSOR_CLASS(klass);

    proc_class->name = "check-file-upload-slave-proc";
    proc_class->start = start;
    proc_class->handle_update = handle_update;
    proc_class->release_resource = release_resource;

    g_type_class_add_private (klass, sizeof (SeafileCheckFileUploadSlaveProcPriv));
}

static void
seafile_check_file_upload_slave_proc_init(SeafileCheckFileUploadSlaveProc *processor)
{
}

static int
decrypt_token(CcnetProcessor *processor)
{
    USE_PRIV;
    int hex_len, encrypted_len, token_len;
    char *encrypted_token = NULL;
    SeafileCrypt *crypt = NULL;
    unsigned char key[16], iv[16];
    char *token = NULL;
    int ret = 0;

    /* raw data is half the length of hexidecimal */
    hex_len = strlen(priv->token);
    if (hex_len % 2 != 0) {
        seaf_warning("[check file upload] invalid length of encrypted token\n");
        ret = -1;
        goto out;
    }

    encrypted_len = hex_len / 2;
    encrypted_token = g_malloc(encrypted_len);
    hex_to_rawdata(priv->token,
                   (unsigned char *)encrypted_token,
                   encrypted_len);

    seafile_generate_enc_key(priv->session_key,
                             strlen(priv->session_key),
                             CURRENT_ENC_VERSION, key, iv);
    crypt = seafile_crypt_new(CURRENT_ENC_VERSION, key, iv);

    if (seafile_decrypt(&token, &token_len, encrypted_token,
                        encrypted_len, crypt) < 0) {
        seaf_warning("[check file upload] failed to decrypt token\n");
        ret = -1;
        goto out;
    }

    g_free(priv->token);
    /* we can use the decrypted data directly, since the trailing null byte is
     * also included when encrypting in the client */
    priv->token = token;

out:
    g_free(crypt);
    g_free(encrypted_token);

    return ret;
}

static void *
check_file_upload(void *vprocessor)
{
    CcnetProcessor *processor = vprocessor;
    USE_PRIV;
    char *perm, *user = NULL;
    char *repo_id = priv->repo_id;

    if (!seaf_repo_manager_repo_exists(seaf->repo_mgr, repo_id)) {
        priv->rsp_code = g_strdup(SC_BAD_REPO);
        priv->rsp_msg = g_strdup(SS_BAD_REPO);
        goto out;
    }

    if (decrypt_token(processor) < 0) {
        priv->rsp_code = g_strdup(SC_ACCESS_DENIED);
        priv->rsp_msg = g_strdup(SS_ACCESS_DENIED);
        goto out;
    }

#if 0
    user = seaf_repo_manager_get_email_by_token(
            seaf->repo_mgr, repo_id, priv->token);
    if (!user) {
        priv->rsp_code = g_strdup(SC_ACCESS_DENIED);
        priv->rsp_msg = g_strdup(SS_ACCESS_DENIED);
        goto out;
    }

    perm = seaf_repo_manager_check_permission(seaf->repo_mgr,
                                              repo_id, user, NULL);
    if (!perm || (strcmp(perm, "r") == 0)) {
        priv->rsp_code = g_strdup(SC_ACCESS_DENIED);
        priv->rsp_msg = g_strdup(SS_ACCESS_DENIED);
        g_free(perm);
        goto out;
    }
    g_free(perm);
#endif

    priv->rsp_code = g_strdup(SC_OK);
    priv->rsp_msg = g_strdup(SS_OK);

out:
    g_free(user);
    return vprocessor;
}

static void 
check_file_upload_cb(void *result)
{
    CcnetProcessor *processor = result;
    USE_PRIV;

    if (processor->delay_shutdown) {
        ccnet_processor_done (processor, FALSE);
        return;
    }

    ccnet_processor_send_response(processor, priv->rsp_code,
                                  priv->rsp_msg, NULL, 0);
    if (strcmp(priv->rsp_code, SC_OK) == 0)
        processor->state = ACCESS_GRANTED;
    else
        ccnet_processor_done(processor, FALSE);
}

static int
start (CcnetProcessor *processor, int argc, char **argv)
{
    char *repo_id, *topath, *token;
    CcnetPeer *peer;
    USE_PRIV;

    if (argc != 3) {
        ccnet_processor_send_response(processor, SC_BAD_ARGS, SS_BAD_ARGS, NULL, 0);
        ccnet_processor_done(processor, FALSE);
        return -1;
    }

    repo_id = argv[0];
    topath = argv[1];
    token = argv[2];

    if (strlen(repo_id) != 36) {
        ccnet_processor_send_response(processor, SC_BAD_ARGS, SS_BAD_ARGS, NULL, 0);
        ccnet_processor_done(processor, FALSE);
        return -1;
    }

    memcpy(priv->repo_id, repo_id, 37);
    priv->token = g_strdup(token);

    peer = ccnet_get_peer(seaf->ccnetrpc_client, processor->peer_id);
    if (!peer || !peer->session_key) {
        seaf_warning("[check file upload slave] session key of peer %.10s is null\n",
                     processor->peer_id);
        ccnet_processor_send_response(processor, SC_BAD_ARGS, SS_BAD_ARGS, NULL, 0);
        ccnet_processor_done(processor, FALSE);
        if (peer)
            g_object_unref(peer);
        return -1;
    }

    priv->session_key = g_strdup(peer->session_key);
    g_object_unref(peer);

    seaf_debug("[check-file-upload] %s repo %.8s.\n", argv[0], repo_id);

    ccnet_processor_thread_create(processor, check_file_upload,
                                  check_file_upload_cb, processor);

    return 0;
}

static void
handle_update (CcnetProcessor *processor,
                 char *code, char *code_msg,
                 char *content, int clen)
{
    USE_PRIV;
    char *token;

    if (processor->state != ACCESS_GRANTED) {
        ccnet_processor_send_response(processor,
                                      SC_BAD_UPDATE_CODE, SS_BAD_UPDATE_CODE,
                                      NULL, 0);
        ccnet_processor_done(processor, FALSE);
        return;
    }

    if (strncmp(code, SC_GET_TOKEN, 3) == 0) {
        token = seaf_token_manager_generate_token(seaf->token_mgr,
                                                  processor->peer_id,
                                                  priv->repo_id);
        ccnet_processor_send_response(processor,
                                      SC_PUT_TOKEN, SS_PUT_TOKEN,
                                      token, strlen(token) + 1);
        ccnet_processor_done(processor, TRUE);
        g_free(token);
        return;
    }

    ccnet_processor_send_response (processor,
                                   SC_BAD_UPDATE_CODE, SS_BAD_UPDATE_CODE,
                                   NULL, 0);
    ccnet_processor_done (processor, FALSE);
}
