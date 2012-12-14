/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include "common.h"
#include <glib/gstdio.h>
#include <ctype.h>

#include <sys/stat.h>
#include <dirent.h>
#include <ccnet.h>
#include "utils.h"

#include "seafile-session.h"
#include "fs-mgr.h"
#include "repo-mgr.h"
#include "seafile-error.h"
#include "seafile-rpc.h"
#include "seafile-config.h"

#ifdef SEAFILE_SERVER
#include "monitor-rpc-wrappers.h"
#include "web-accesstoken-mgr.h"
#endif

#include "gc.h"
#include "log.h"

#ifndef SEAFILE_SERVER
#include "../daemon/vc-utils.h"

#ifdef WIN32
static char *normal_index_path(const char *path)
{
    char *newpath = g_strdup(path);
    char *p = newpath;

    while(*p != '\0') {
        if(*p == '\\') *p = '/';
        ++p;
    }

    return newpath;
}
#else
static char *normal_index_path(const char *path)
{
    return g_strdup(path);
}
#endif

#endif  /* SEAFILE_SERVER */


/* -------- Utilities -------- */
static GList *
convert_repo_list (GList *inner_repos)
{
    GList *ret = NULL, *ptr;

    for (ptr = inner_repos; ptr; ptr=ptr->next) {
        SeafRepo *r = ptr->data;
#ifndef SEAFILE_SERVER
        /* Don't display repos without worktree. */
        if (r->head == NULL || r->worktree_invalid)
            continue;
#endif

        SeafileRepo *repo = seafile_repo_new ();
        g_object_set (repo, "id", r->id, "name", r->name,
                      "desc", r->desc, "encrypted", r->encrypted,
                      NULL);

#ifndef SEAFILE_SERVER
    g_object_set (repo, "worktree-changed", r->wt_changed,
                  "worktree-checktime", r->wt_check_time,
                  "worktree-invalid", r->worktree_invalid,
                  "last-sync-time", r->last_sync_time,
                  "index-corrupted", r->index_corrupted,
                  NULL);

    g_object_set (repo, "worktree", r->worktree,
                  /* "auto-sync", r->auto_sync, */
                  "head_branch", r->head ? r->head->name : NULL,
                  "relay-id", r->relay_id,
                  "auto-sync", r->auto_sync,
                  NULL);

    g_object_set (repo, "passwd", r->passwd, NULL);

    g_object_set (repo,
                  "last-modify", seafile_repo_last_modify(r->id, NULL),
                  NULL);

    g_object_set (repo, "no-local-history", r->no_local_history, NULL);
#endif

        ret = g_list_prepend (ret, repo);
    }
    ret = g_list_reverse (ret);

    return ret;
}

GList *
seafile_list_dir_by_path(const char *commit_id, const char *path, GError **error)
{
    if (!commit_id || !path) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Args can't be NULL");
        return NULL;
    }

    SeafCommit *commit;
    commit = seaf_commit_manager_get_commit(seaf->commit_mgr, commit_id);

    if (!commit) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_COMMIT, "No such commit");
        return NULL;
    }

    char *p = g_strdup(path);
    int len = strlen(p);

    /* strip trailing backslash */
    while (len > 0 && p[len-1] == '/') {
        p[len-1] = '\0';
        len--;
    }

    SeafDir *dir;
    SeafDirent *dent;
    SeafileDirent *d;

    GList *ptr;
    GList *res = NULL;

    dir = seaf_fs_manager_get_seafdir_by_path (seaf->fs_mgr, commit->root_id,
                                               p, error);
    if (!dir) {
        seaf_warning ("Can't find seaf dir for %s\n", path);
        goto out;
    }

    for (ptr = dir->entries; ptr != NULL; ptr = ptr->next) {
        dent = ptr->data;
        d = g_object_new (SEAFILE_TYPE_DIRENT,
                          "obj_id", dent->id,
                          "obj_name", dent->name,
                          "mode", dent->mode,
                          NULL);
        res = g_list_prepend (res, d);
    }

    seaf_dir_free (dir);
    res = g_list_reverse (res);

 out:

    g_free (p);
    seaf_commit_unref (commit);
    return res;
}

char *
seafile_get_dirid_by_path(const char *commit_id, const char *path, GError **error)
{
    char *res = NULL;
    if (!commit_id || !path) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Args can't be NULL");
        return NULL;
    }

    SeafCommit *commit;
    commit = seaf_commit_manager_get_commit(seaf->commit_mgr, commit_id);

    if (!commit) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_COMMIT, "No such commit");
        return NULL;
    }

    char *p = g_strdup(path);
    int len = strlen(p);

    /* strip trailing backslash */
    while (len > 0 && p[len-1] == '/') {
        p[len-1] = '\0';
        len--;
    }

    SeafDir *dir;
    dir = seaf_fs_manager_get_seafdir_by_path (seaf->fs_mgr, commit->root_id,
                                               p, error);
    if (!dir) {
        seaf_warning ("Can't find seaf dir for %s\n", path);
        goto out;
    }

    res = g_strdup (dir->dir_id);
    seaf_dir_free (dir);

 out:

    g_free (p);
    seaf_commit_unref (commit);
    return res;
}

/*
 * RPC functions only available for clients.
 */

#ifndef SEAFILE_SERVER

#include "sync-mgr.h"

GObject *
seafile_get_session_info (GError **error)
{
    SeafileSessionInfo *info;

    info = seafile_session_info_new ();
    g_object_set (info, "datadir", seaf->seaf_dir, NULL);
    return (GObject *) info;
}

int
seafile_set_config (const char *key, const char *value, GError **error)
{
    return seafile_session_config_set_string(seaf, key, value);
}

char *
seafile_get_config (const char *key, GError **error)
{
    return seafile_session_config_get_string(seaf, key);
}

#if 0
const gchar*
seafile_create_repo (const char *name,
                     const char *description,
                     const char *worktree,
                     const char *passwd,
                     const char *relay_id,
                     int keep_local_history,
                     GError **error)
{
    SeafRepo *repo;
    SeafBranch *branch;
    SeafCommit *commit;

    if (!name || !description) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Name and description should not be null");
        return NULL;
    }

    /* check worktree before create repo */
    if (!worktree || worktree[0] == '\0') {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid work directory");
        return NULL;
    }

    if (g_access(worktree, F_OK) != 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid work directory");
        return NULL;
    }

    repo = seaf_repo_manager_create_new_repo (seaf->repo_mgr, name, description);
    if (!repo) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Error when create repo");
        return NULL;
    }

    if (passwd != NULL && passwd[0] != '\0') {
        repo->encrypted = TRUE;
        repo->enc_version = CURRENT_ENC_VERSION;
        seaf_repo_generate_magic (repo, passwd);
        seaf_repo_manager_set_repo_passwd (seaf->repo_mgr,
                                           repo,
                                           passwd);
    }

    seaf_repo_manager_set_repo_worktree (seaf->repo_mgr, repo, worktree);
    seaf_repo_manager_set_repo_relay_id (seaf->repo_mgr, repo, relay_id);

    commit = seaf_commit_new (NULL,
                              repo->id,
                              EMPTY_SHA1,
                              seaf->session->base.user_name,
                              seaf->session->base.id,
                              description,
                              0);
    commit->repo_name = g_strdup(name);
    commit->repo_desc = g_strdup(description);
    if (passwd && passwd[0] != '\0') {
        commit->encrypted = TRUE;
        commit->enc_version = repo->enc_version;
        commit->magic = g_strdup(repo->magic);
    } else
        commit->encrypted = FALSE;

    if (!keep_local_history) {
        repo->no_local_history = TRUE;
        commit->no_local_history = TRUE;
    }

    if (seaf_commit_manager_add_commit (seaf->commit_mgr, commit) < 0)
        return NULL;

    branch = seaf_branch_new ("local", repo->id, commit->commit_id);
    seaf_branch_manager_add_branch (seaf->branch_mgr, branch);

    seaf_repo_set_head (repo, branch, commit);

    seaf_commit_unref (commit);
    seaf_branch_unref (branch);

    /* Publish a message, for applet to notify in the system tray */
    GString *buf = g_string_new (NULL);
    g_string_append_printf (buf, "%s\t%s", (char *)worktree, repo->id);

    seaf_mq_manager_publish_notification (seaf->mq_mgr,
                                          "repo.created",
                                          buf->str);
    g_string_free (buf, TRUE);

    return g_strdup(repo->id);
}
#endif

int
seafile_edit_repo (const char *repo_id,
                   const char *name,
                   const char *description,
                   GError **error)
{
    SeafRepo *repo;
    SeafCommit *commit, *parent;

    if (!name && !description) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "At least one argument should be non-null");
        return -1;
    }

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "No such repository");
        return -1;
    }

    pthread_mutex_lock (&repo->lock);

    /*
     * We only change repo_name or repo_desc, so just copy the head commit
     * and change these two fields.
     */
    parent = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                             repo->head->commit_id);
    commit = seaf_commit_new (NULL,
                              repo->id,
                              parent->root_id,
                              seaf->session->base.user_name,
                              seaf->session->base.id,
                              description,
                              0);
    commit->parent_id = g_strdup(parent->commit_id);
    commit->repo_name = g_strdup(name);
    commit->repo_desc = g_strdup(description);
    if (seaf_commit_manager_add_commit (seaf->commit_mgr, commit) < 0) {
        pthread_mutex_unlock (&repo->lock);
        return -1;
    }

    seaf_branch_set_commit (repo->head, commit->commit_id);
    seaf_branch_manager_update_branch (seaf->branch_mgr, repo->head);
    /*seaf_repo_set_head (repo, commit);*/

    /* update the repo'name and desc so that seaf-list-repo can show
     * the latest info */

    char *orig_name = repo->name;
    char *orig_desc = repo->desc;

    repo->name = g_strdup (name);
    repo->desc = g_strdup (description);

    g_free (orig_name);
    g_free (orig_desc);
    seaf_commit_unref (commit);

    g_signal_emit_by_name (seaf, "repo-committed", repo);

    pthread_mutex_unlock (&repo->lock);

    return 0;
}


int
seafile_repo_last_modify(const char *repo_id, GError **error)
{
    SeafRepo *repo;
    SeafCommit *c;
    char *commit_id;
    int ctime = 0;

    if (!repo_id) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return -1;
    }

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_REPO, "No such repository");
        return -1;
    }

    if (!repo->head) {
        SeafBranch *branch =
            seaf_branch_manager_get_branch (seaf->branch_mgr,
                                            repo->id, "master");
        if (branch != NULL) {
            commit_id = g_strdup (branch->commit_id);
            seaf_branch_unref (branch);
        } else {
            g_warning ("[repo-mgr] Failed to get repo %s branch master\n",
                       repo_id);
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_REPO,
                         "No head and branch master");
            return -1;
        }
    } else {
        commit_id = g_strdup (repo->head->commit_id);
    }

    c = seaf_commit_manager_get_commit (seaf->commit_mgr, commit_id);
    g_free (commit_id);
    if (!c)
        return -1;

    ctime = c->ctime;
    seaf_commit_unref (c);
    return ctime;
}

int
seafile_add (const char *repo_id, const char *path, GError **error)
{
    SeafRepo *repo;
    char *normalpath = NULL;

    if (!path || !repo_id) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return -1;
    }

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "No such repository");
        return -1;
    }

    pthread_mutex_lock (&repo->lock);

    normalpath = normal_index_path (path);
    if (seaf_repo_index_add (repo, normalpath) < 0) {
        g_set_error (error, SEAFILE_DOMAIN, -1, "Failed to add %s", normalpath);
        pthread_mutex_unlock (&repo->lock);
        g_free (normalpath);
        return -1;
    }

    pthread_mutex_unlock (&repo->lock);
    g_free (normalpath);
    return 0;
}

int
seafile_rm (const char *repo_id, const char *path, GError **error)
{
    SeafRepo *repo;
    char *normalpath = NULL;

    if (!path || !repo_id) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return -1;
    }

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "No such repository");
        return -1;
    }

    pthread_mutex_lock (&repo->lock);

    normalpath = normal_index_path (path);
    if (seaf_repo_index_rm (repo, normalpath) < 0) {
        g_set_error (error, SEAFILE_DOMAIN, -1, "Failed to remove %s", normalpath);
        pthread_mutex_unlock (&repo->lock);
        g_free (normalpath);
        return -1;
    }

    pthread_mutex_unlock (&repo->lock);
    g_free (normalpath);

    return 0;
}

static int check_whitespace(const char *str)
{
    const char *p;

    for (p = str; *p != '\0'; p++) {
        if (isspace(*p))
            return 1;
    }

    return 0;
}

int
seafile_branch_add (const char *repo_id, const char *branch_name,
                    const char *original_branch,
                    GError **error)
{
    SeafRepo *repo;
    SeafBranch *branch;

    if (!repo_id || !branch_name) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return -1;
    }

    /* check branch name with whitespace */
    if (check_whitespace(branch_name)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Branch name cannot include whitespace");
        return -1;
    }

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "No such repository");
        return -1;
    }

    if (original_branch == NULL || strlen(original_branch) == 0)
        original_branch = "HEAD"; /* default create branch from head */

    if (strcmp(original_branch, "HEAD") == 0) {
        if (!repo->head) {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                "Try to create branch from HEAD, but HEAD branch not exists.");
            return -1;
        } else
            branch = seaf_branch_new (branch_name, repo->id,
                                      repo->head->commit_id);
    } else {
        SeafBranch *old_branch;
        old_branch = seaf_branch_manager_get_branch (
            seaf->branch_mgr, repo_id, original_branch);
        if (!old_branch) {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                         "Original branch %s not exists.", original_branch);
            return -1;
        }
        branch = seaf_branch_new (branch_name, repo->id, old_branch->commit_id);
        seaf_branch_unref (old_branch);
    }

    seaf_branch_manager_add_branch (seaf->branch_mgr, branch);
    seaf_branch_unref (branch);

    return 0;
}

const char *
seafile_commit(const char *repo_id, const char *desc, GError **error)
{
    SeafRepo *repo;
    char *commit_id = NULL;

    if (!repo_id || !desc) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return NULL;
    }

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "No such repository");
        return NULL;
    }

    pthread_mutex_lock (&repo->lock);

    gboolean unmerged = seaf_repo_is_index_unmerged (repo);

    if (seaf_repo_index_add (repo, "") < 0) {
        g_set_error (error, SEAFILE_DOMAIN, -1, "Failed to add");
        goto unlock_and_return;
    }

    commit_id = seaf_repo_index_commit (repo, desc, unmerged, NULL, error);
    if (!commit_id) {
        goto unlock_and_return;
    }

unlock_and_return:
    pthread_mutex_unlock (&repo->lock);

    return commit_id;
}

int
seafile_checkout (const char *repo_id,
                  const char *passwd,
                  GError **error)
{
    SeafRepo *repo;
    if (!is_repo_id_valid(repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return -1;
    }

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "No such repository");
        return -1;
    }

    if (repo->encrypted && !passwd) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Password can not be empty");
        return -1;
    }

    if (repo->encrypted) {
        if (repo->enc_version >= 1 &&
            seaf_repo_verify_passwd (repo, passwd) < 0) {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, "Incorrect password");
            return -1;
        }

        if (seaf_repo_manager_set_repo_passwd (seaf->repo_mgr,
                                               repo,
                                               passwd) < 0) {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, "Internal data error");
            return -1;
        }
    }

    return seaf_repo_manager_add_checkout_task(seaf->repo_mgr, repo,
                                               seaf->worktree_dir,
                                               NULL, NULL);
}

GObject *
seafile_get_checkout_task (const char *repo_id, GError **error)
{
    if (!repo_id) {
        seaf_warning ("Invalid args\n");
        return NULL;
    }

    CheckoutTask *task;
    task = seaf_repo_manager_get_checkout_task(seaf->repo_mgr,
                                               repo_id);
    if (!task)
        return NULL;

    SeafileCheckoutTask *c_task = g_object_new
        (SEAFILE_TYPE_CHECKOUT_TASK,
         "repo_id", task->repo_id,
         "worktree", task->worktree,
         "total_files", task->total_files,
         "finished_files", task->finished_files,
         NULL);

    return (GObject *)c_task;
}

int
seafile_merge (const char *repo_id, const char *branch, GError **error)
{
    SeafRepo *repo;
    char *err_msgs = NULL;
    gboolean unused;

    if (!repo_id || !branch) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return -1;
    }

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "No such repository");
        return -1;
    }

    pthread_mutex_lock (&repo->lock);

    if (seaf_repo_merge (repo, branch, &err_msgs, &unused) < 0) {
        g_set_error (error, SEAFILE_DOMAIN, -1, "%s", err_msgs);
        g_free (err_msgs);
        pthread_mutex_unlock (&repo->lock);
        return -1;
    }

    pthread_mutex_unlock (&repo->lock);

    return 0;
}


char *
seafile_gen_default_worktree (const char *worktree_parent,
                              const char *repo_name,
                              GError **error)
{
    if (!worktree_parent || !repo_name) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Empty args");
        return NULL;
    }

    return seaf_clone_manager_gen_default_worktree (seaf->clone_mgr,
                                                    worktree_parent,
                                                    repo_name);
}

char *
seafile_clone (const char *repo_id,
               const char *relay_id,
               const char *repo_name,
               const char *worktree,
               const char *token,
               const char *passwd,
               const char *peer_addr,
               const char *peer_port,
               const char *email,
               GError **error)
{
    if (!repo_id || strlen(repo_id) != 36) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return NULL;
    }

    if (!relay_id || strlen(relay_id) != 40) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid peer id");
        return NULL;
    }

    if (!worktree) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Worktre must be specified");
        return NULL;
    }

    if (!token || !peer_addr || !peer_port || !email ) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Argument can't be NULL");
        return NULL;
    }

    return seaf_clone_manager_add_task (seaf->clone_mgr,
                                        repo_id, relay_id,
                                        repo_name, token,
                                        passwd, worktree,
                                        peer_addr, peer_port,
                                        email, error);
}

char *
seafile_download (const char *repo_id,
                  const char *relay_id,
                  const char *repo_name,
                  const char *wt_parent,
                  const char *token,
                  const char *passwd,
                  const char *peer_addr,
                  const char *peer_port,
                  const char *email,
                  GError **error)
{
    if (!repo_id || strlen(repo_id) != 36) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid repo id");
        return NULL;
    }

    if (!relay_id || strlen(relay_id) != 40) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid peer id");
        return NULL;
    }

    if (!wt_parent) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Worktre must be specified");
        return NULL;
    }

    if (!token || !peer_addr || !peer_port || !email ) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Argument can't be NULL");
        return NULL;
    }

    return seaf_clone_manager_add_download_task (seaf->clone_mgr,
                                                 repo_id, relay_id,
                                                 repo_name, token,
                                                 passwd, wt_parent,
                                                 peer_addr, peer_port,
                                                 email, error);
}

int
seafile_cancel_clone_task (const char *repo_id, GError **error)
{
    return seaf_clone_manager_cancel_task (seaf->clone_mgr, repo_id);
}

int
seafile_remove_clone_task (const char *repo_id, GError **error)
{
    return seaf_clone_manager_remove_task (seaf->clone_mgr, repo_id);
}

GList *
seafile_get_clone_tasks (GError **error)
{
    GList *tasks, *ptr;
    GList *ret = NULL;
    CloneTask *task;
    SeafileCloneTask *t;

    tasks = seaf_clone_manager_get_tasks (seaf->clone_mgr);
    for (ptr = tasks; ptr != NULL; ptr = ptr->next) {
        task = ptr->data;
        t = g_object_new (SEAFILE_TYPE_CLONE_TASK,
                          "state", clone_task_state_to_str(task->state),
                          "error_str", clone_task_error_to_str(task->error),
                          "repo_id", task->repo_id,
                          "peer_id", task->peer_id,
                          "repo_name", task->repo_name,
                          "worktree", task->worktree,
                          "tx_id", task->tx_id,
                          NULL);
        ret = g_list_prepend (ret, t);
    }

    g_list_free (tasks);
    return ret;
}

int
seafile_sync (const char *repo_id, const char *peer_id, GError **error)
{
    if (!repo_id) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Repo ID should not be null");
        return -1;
    }

    return seaf_sync_manager_add_sync_task (seaf->sync_mgr, repo_id, peer_id,
                                            NULL, FALSE, error);
}

static void get_task_size(TransferTask *task, gint64 *rsize, gint64 *dsize)
{
    if (task->runtime_state == TASK_RT_STATE_INIT
        || task->runtime_state == TASK_RT_STATE_COMMIT
        || task->runtime_state == TASK_RT_STATE_FS
        || task->runtime_state == TASK_RT_STATE_FINISHED) {
        *rsize = task->rsize;
        *dsize = task->dsize;
    }
    if (task->runtime_state == TASK_RT_STATE_DATA) {
        if (task->type == TASK_TYPE_DOWNLOAD) {
            *dsize = task->block_list->n_valid_blocks;
            *rsize = task->block_list->n_blocks - *dsize;
        } else {
            *dsize = task->n_uploaded;
            *rsize = task->block_list->n_blocks - *dsize;
        }
    }
}

static SeafileTask *
convert_task (TransferTask *task)
{
    gint64 rsize = 0, dsize = 0;
    SeafileTask *t = seafile_task_new();

    get_task_size (task, &rsize, &dsize);

    g_assert (strlen(task->repo_id) == 36);
    g_object_set (t, "tx_id", task->tx_id,
                  "repo_id", task->repo_id,
                  "dest_id", task->dest_id,
                  "from_branch", task->from_branch,
                  "to_branch", task->to_branch,
                  "state", task_state_to_str(task->state),
                  "rt_state", task_rt_state_to_str(task->runtime_state),
                  "rsize", rsize, "dsize", dsize,
                  "error_str", task_error_str(task->error),
                  NULL);

    if (task->type == TASK_TYPE_DOWNLOAD) {
        g_object_set (t, "ttype", "download", NULL);
        if (task->runtime_state == TASK_RT_STATE_DATA) {
            g_object_set (t, "block_total", task->block_list->n_blocks,
                          "block_done", task->block_list->n_valid_blocks, NULL);
            g_object_set (t, "rate", (int)transfer_task_get_rate(task), NULL);
        }
    } else {
        g_object_set (t, "ttype", "upload", NULL);
        if (task->runtime_state == TASK_RT_STATE_DATA) {
            g_object_set (t, "block_total", task->block_list->n_blocks,
                          "block_done", task->n_uploaded, NULL);
            g_object_set (t, "rate", (int)transfer_task_get_rate(task), NULL);
        }
    }

    return t;
}


GObject *
seafile_find_transfer_task (const char *repo_id, GError *error)
{
    TransferTask *task;

    task = seaf_transfer_manager_find_transfer_by_repo (
        seaf->transfer_mgr, repo_id);
    if (!task)
        return NULL;

    return (GObject *)convert_task (task);
}


GObject *
seafile_get_repo_sync_info (const char *repo_id, GError **error)
{
    SyncInfo *info;

    info = seaf_sync_manager_get_sync_info (seaf->sync_mgr, repo_id);
    if (!info)
        return NULL;

    SeafileSyncInfo *sinfo;
    sinfo = g_object_new (SEAFILE_TYPE_SYNC_INFO,
                          "repo_id", info->repo_id,
                          "head_commit", info->head_commit,
                          "deleted_on_relay", info->deleted_on_relay,
                          "need_fetch", info->need_fetch,
                          "need_upload", info->need_upload,
                          "need_merge", info->need_merge,
                          /* "last_sync_time", info->last_sync_time,  */
                          NULL);

    return (GObject *)sinfo;
}


GObject *
seafile_get_repo_sync_task (const char *repo_id, GError **error)
{
    SyncInfo *info = seaf_sync_manager_get_sync_info (seaf->sync_mgr, repo_id);
    if (!info || !info->current_task)
        return NULL;

    SyncTask *task = info->current_task;

    SeafileSyncTask *s_task;
    s_task = g_object_new (SEAFILE_TYPE_SYNC_TASK,
                           "is_sync_lan", task->is_sync_lan,
                           "force_upload", task->force_upload,
                           "state", sync_state_to_str(task->state),
                           "error", sync_error_to_str(task->error),
                           "tx_id", task->tx_id,
                           "dest_id", task->dest_id,
                           "repo_id", info->repo_id,
                           NULL);

    return (GObject *)s_task;
}

GList *
seafile_get_sync_task_list (GError **error)
{
    GHashTable *sync_info_tbl = seaf->sync_mgr->sync_infos;
    GHashTableIter iter;
    SeafileSyncTask *s_task;
    GList *task_list = NULL;
    gpointer key, value;

    g_hash_table_iter_init (&iter, sync_info_tbl);
    while (g_hash_table_iter_next (&iter, &key, &value)) {
        SyncInfo *info = value;
        if (!info->in_sync)
            continue;
        SyncTask *task = info->current_task;
        if (!task)
            continue;
        s_task = g_object_new (SEAFILE_TYPE_SYNC_TASK,
                               "is_sync_lan", task->is_sync_lan,
                               "force_upload", task->force_upload,
                               "state", sync_state_to_str(task->state),
                               "error", sync_error_to_str(task->error),
                               "dest_id", task->dest_id,
                               "repo_id", info->repo_id,
                               "tx_id", task->tx_id,
                               NULL);
        task_list = g_list_prepend (task_list, s_task);
    }

    return task_list;
}


int
seafile_set_repo_property (const char *repo_id,
                           const char *key,
                           const char *value,
                           GError **error)
{
    int ret;

    if (repo_id == NULL || key == NULL || value == NULL) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Arguments should not be empty");
        return -1;
    }

    SeafRepo *repo;
    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_REPO, "Can't find Repo %s", repo_id);
        return -1;
    }

    ret = seaf_repo_manager_set_repo_property (seaf->repo_mgr,
                                               repo->id, key, value);
    if (ret < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_INTERNAL,
                     "Failed to set key for repo %s", repo_id);
        return -1;
    }

    return 0;
}

gchar *
seafile_get_repo_property (const char *repo_id,
                           const char *key,
                           GError **error)
{
    char *value = NULL;

    if (!repo_id || !key) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Arguments should not be empty");
        return NULL;
    }

    SeafRepo *repo;
    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_REPO, "Can't find Repo %s", repo_id);
        return NULL;
    }

    value = seaf_repo_manager_get_repo_property (seaf->repo_mgr, repo->id, key);
    return value;
}

int
seafile_calc_dir_size (const char *path, GError **error)
{
    if (!path) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return -1;
    }

    gint64 size_64 = ccnet_calc_directory_size(path, error);
    if (size_64 < 0) {
        seaf_warning ("failed to calculate dir size for %s\n", path);
        return -1;
    }

    /* get the size in MB */
    int size = (int) (size_64 >> 20);
    return size;
}

int
seafile_disable_auto_sync (GError **error)
{
    return seaf_sync_manager_disable_auto_sync (seaf->sync_mgr);
}

int
seafile_enable_auto_sync (GError **error)
{
    return seaf_sync_manager_enable_auto_sync (seaf->sync_mgr);
}

int seafile_is_auto_sync_enabled (GError **error)
{
    return seaf_sync_manager_is_auto_sync_enabled (seaf->sync_mgr);
}


#endif  /* not define SEAFILE_SERVER */

/*
 * RPC functions available for both clients and server.
 */

#include "diff-simple.h"

inline static const char*
get_diff_status_str(char status)
{
    if (status == DIFF_STATUS_ADDED)
        return "add";
    if (status == DIFF_STATUS_DELETED)
        return "del";
    if (status == DIFF_STATUS_MODIFIED)
        return "mod";
    if (status == DIFF_STATUS_RENAMED)
        return "mov";
    if (status == DIFF_STATUS_DIR_ADDED)
        return "newdir";
    if (status == DIFF_STATUS_DIR_DELETED)
        return "deldir";
    return NULL;
}

GList *
seafile_diff (const char *repo_id, const char *arg1, const char *arg2, GError **error)
{
    SeafRepo *repo;
    char *err_msgs = NULL;
    GList *diff_entries, *p;
    GList *ret = NULL;

    if (!repo_id || !arg1 || !arg2) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return NULL;
    }

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "No such repository");
        return NULL;
    }

    diff_entries = seaf_repo_diff (repo, arg1, arg2, &err_msgs);
    if (err_msgs) {
        g_set_error (error, SEAFILE_DOMAIN, -1, "%s", err_msgs);
        g_free (err_msgs);
#ifdef SEAFILE_SERVER
        seaf_repo_unref (repo);
#endif
        return NULL;
    }

#ifdef SEAFILE_SERVER
    seaf_repo_unref (repo);
#endif

    for (p = diff_entries; p != NULL; p = p->next) {
        DiffEntry *de = p->data;
        SeafileDiffEntry *entry = g_object_new (
            SEAFILE_TYPE_DIFF_ENTRY,
            "status", get_diff_status_str(de->status),
            "name", de->name,
            "new_name", de->new_name,
            NULL);
        ret = g_list_prepend (ret, entry);
    }

    for (p = diff_entries; p != NULL; p = p->next) {
        DiffEntry *de = p->data;
        diff_entry_free (de);
    }
    g_list_free (diff_entries);

    return g_list_reverse (ret);
}

GList *
seafile_list_dir (const char *dir_id, GError **error)
{
    SeafDir *dir;
    SeafDirent *dent;
    SeafileDirent *d;
    GList *res = NULL;
    GList *p;

    dir = seaf_fs_manager_get_seafdir (seaf->fs_mgr, dir_id);
    if (!dir) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_DIR_ID, "Bad dir id");
        return NULL;
    }

    for (p = dir->entries; p != NULL; p = p->next) {
        dent = p->data;
        d = g_object_new (SEAFILE_TYPE_DIRENT,
                          "obj_id", dent->id,
                          "obj_name", dent->name,
                          "mode", dent->mode,
                          NULL);
        res = g_list_prepend (res, d);
    }

    seaf_dir_free (dir);
    res = g_list_reverse (res);
    return res;
}

GList *
seafile_branch_gets (const char *repo_id, GError **error)
{
    GList *blist = seaf_branch_manager_get_branch_list(seaf->branch_mgr,
                                                       repo_id);
    GList *ptr;
    GList *ret = NULL;

    for (ptr = blist; ptr; ptr=ptr->next) {
        SeafBranch *b = ptr->data;
        SeafileBranch *branch = seafile_branch_new ();
        g_object_set (branch, "repo_id", b->repo_id, "name", b->name,
                      "commit_id", b->commit_id, NULL);
        ret = g_list_prepend (ret, branch);
        seaf_branch_unref (b);
    }
    ret = g_list_reverse (ret);
    g_list_free (blist);
    return ret;
}

GList*
seafile_get_repo_list (int start, int limit, GError **error)
{
    GList *repos = seaf_repo_manager_get_repo_list(seaf->repo_mgr, start, limit);
    GList *ret = NULL;

    ret = convert_repo_list (repos);

#ifdef SEAFILE_SERVER
    GList *ptr;
    for (ptr = repos; ptr != NULL; ptr = ptr->next)
        seaf_repo_unref ((SeafRepo *)ptr->data);
#endif
    g_list_free (repos);

    return ret;
}

GObject*
seafile_get_repo (const char *repo_id, GError **error)
{
    SeafRepo *r;

    if (!repo_id) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return NULL;
    }
    r = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    /* Don't return repo that's not checked out. */
    if (r == NULL)
        return NULL;

#ifndef SEAFILE_SERVER
    if (r->head == NULL || r->worktree_invalid)
        return NULL;
#endif

    SeafileRepo *repo = seafile_repo_new ();
    g_object_set (repo, "id", r->id, "name", r->name,
                  "desc", r->desc, "encrypted", r->encrypted,
                  "head_branch", r->head ? r->head->name : NULL,
                  "head_cmmt_id", r->head ? r->head->commit_id : NULL,
                  NULL);
#ifndef SEAFILE_SERVER
    g_object_set (repo, "worktree-changed", r->wt_changed,
                  "worktree-checktime", r->wt_check_time,
                  "worktree-invalid", r->worktree_invalid,
                  "last-sync-time", r->last_sync_time,
                  "index-corrupted", r->index_corrupted,
                  NULL);

    g_object_set (repo, "worktree", r->worktree,
                  "relay-id", r->relay_id,
                  "auto-sync", r->auto_sync,
                  NULL);

    g_object_set (repo, "passwd", r->passwd, NULL);

    g_object_set (repo,
                  "last-modify", seafile_repo_last_modify(r->id, NULL),
                  NULL);

    g_object_set (repo, "no-local-history", r->no_local_history, NULL);
#endif  /* SEAFILE_SERVER */

#ifdef SEAFILE_SERVER
    seaf_repo_unref (r);
#endif

    return (GObject *)repo;
}

inline SeafileCommit *
convert_to_seafile_commit (SeafCommit *c)
{
    SeafileCommit *commit = seafile_commit_new ();
    g_object_set (commit,
                  "id", c->commit_id,
                  "creator_name", c->creator_name,
                  "creator", c->creator_id,
                  "desc", c->desc,
                  "ctime", c->ctime,
                  "repo_id", c->repo_id,
                  "root_id", c->root_id,
                  "parent_id", c->parent_id,
                  "second_parent_id", c->second_parent_id,
                  NULL);
    return commit;
}

GObject*
seafile_get_commit (const gchar *id, GError **error)
{
    SeafileCommit *commit;
    SeafCommit *c;

    c = seaf_commit_manager_get_commit (seaf->commit_mgr, id);
    if (!c)
        return NULL;

    commit = convert_to_seafile_commit (c);
    seaf_commit_unref (c);
    return (GObject *)commit;
}

static void
free_commit_list (GList *commits)
{
    SeafileCommit *c;
    GList *ptr;

    for (ptr = commits; ptr; ptr = ptr->next) {
        c = ptr->data;
        g_object_unref (c);
    }
    g_list_free (commits);
}

struct CollectParam {
    int offset;
    int limit;
    int count;
    GList *commits;
};

static gboolean
get_commit (SeafCommit *c, void *data, gboolean *stop)
{
    struct CollectParam *cp = data;

    /* if offset = 1, limit = 1, we should stop when the count = 2 */
    if (cp->limit > 0 && cp->count >= cp->offset + cp->limit) {
        *stop = TRUE;
        return TRUE;  /* TRUE to indicate no error */
    }

    if (cp->count >= cp->offset) {
        SeafileCommit *commit = convert_to_seafile_commit (c);
        cp->commits = g_list_prepend (cp->commits, commit);
    }

    ++cp->count;
    return TRUE;                /* TRUE to indicate no error */
}


GList*
seafile_get_commit_list (const char *repo_id,
                         int offset,
                         int limit,
                         GError **error)
{
    SeafRepo *repo;
    GList *commits = NULL;
    gboolean ret;
    struct CollectParam cp;
    char *commit_id;

    /* correct parameter */
    if (offset < 0)
        offset = 0;

    if (!repo_id) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return NULL;
    }

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_REPO, "No such repository");
        return NULL;
    }

    if (!repo->head) {
        SeafBranch *branch =
            seaf_branch_manager_get_branch (seaf->branch_mgr,
                                            repo->id, "master");
        if (branch != NULL) {
            commit_id = g_strdup (branch->commit_id);
            seaf_branch_unref (branch);
        } else {
            g_warning ("[repo-mgr] Failed to get repo %s branch master\n",
                       repo_id);
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_REPO,
                         "No head and branch master");
#ifdef SEAFILE_SERVER
            seaf_repo_unref (repo);
#endif
            return NULL;
        }
    } else {
        commit_id = g_strdup (repo->head->commit_id);
    }

#ifdef SEAFILE_SERVER
    seaf_repo_unref (repo);
#endif

    /* Init CollectParam */
    cp.offset = offset;
    cp.limit = limit;
    cp.count = 0;
    cp.commits = NULL;

    ret = seaf_commit_manager_traverse_commit_tree (
        seaf->commit_mgr, commit_id, get_commit, &cp);
    g_free (commit_id);

    if (!ret) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_LIST_COMMITS, "Failed to list commits");
        free_commit_list (commits);
        return NULL;
    }

    commits = g_list_reverse (cp.commits);
    return commits;
}

int
seafile_destroy_repo (const char *repo_id, GError **error)
{
    SeafRepo *repo;

    if (!repo_id) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return -1;
    }

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "No such repository");
        return -1;
    }

#ifndef SEAFILE_SERVER
    if (repo->auto_sync)
        seaf_wt_monitor_unwatch_repo (seaf->wt_monitor, repo_id);

    SyncInfo *info = seaf_sync_manager_get_sync_info (seaf->sync_mgr, repo_id);

    /* If we are syncing the repo,
     * we just mark the repo as deleted and let sync-mgr actually delete it.
     * Otherwise we are safe to delete the repo.
     */
    char *worktree = g_strdup (repo->worktree);
    if (info != NULL && info->in_sync) {
        seaf_repo_manager_mark_repo_deleted (seaf->repo_mgr, repo);
    } else {
        seaf_repo_manager_del_repo (seaf->repo_mgr, repo);
    }

    /* Publish a message, for applet to notify in the system tray */
    seaf_mq_manager_publish_notification (seaf->mq_mgr,
                                          "repo.removed",
                                          worktree);
    g_free (worktree);
#else
    seaf_repo_manager_del_repo (seaf->repo_mgr, repo);
    seaf_share_manager_remove_repo (seaf->share_mgr, repo->id);
#endif

    return 0;
}

int
seafile_gc (GError **error)
{
    return gc_start ();
}

int
seafile_gc_get_progress (GError **error)
{
    int progress = gc_get_progress ();

    if (progress < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GC_NOT_STARTED, "GC is not running");
        return -1;
    }

    return progress;
}

#ifndef SEAFILE_SERVER
int
seafile_upload_file (const char *filepath, const char *peerid, const char *repoid,
                     const char *topath, GError **error)
{
    if (!repoid || strlen(repoid) != 36 ||
        !peerid || !filepath || !topath) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Bad arguments");
        return -1;
    }

    return seaf_repo_manager_upload_file (seaf->repo_mgr, filepath,
                                          peerid, repoid, topath, error);
}
#endif

/*
 * RPC functions only available for server.
 */

#ifdef SEAFILE_SERVER
int
seafile_is_repo_owner (const char *email,
                       const char *repo_id,
                       GError **error)
{
    char *owner = seaf_repo_manager_get_repo_owner (seaf->repo_mgr, repo_id);
    if (!owner) {
        /* g_warning ("Failed to get owner info for repo %s.\n", repo_id); */
        return 0;
    }

    if (strcmp(owner, email) != 0) {
        g_free (owner);
        return 0;
    }

    g_free (owner);
    return 1;
}

char *
seafile_get_repo_owner (const char *repo_id, GError **error)
{
    if (!repo_id) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return NULL;
    }

    char *owner = seaf_repo_manager_get_repo_owner (seaf->repo_mgr, repo_id);
    if (!owner){
        g_warning ("Failed to get repo owner for repo %s.\n", repo_id);
    }

    return owner;
}


GList *
seafile_list_owned_repos (const char *email, GError **error)
{
    GList *ret = NULL;
    GList *repos, *ptr;
    SeafRepo *r;
    SeafileRepo *repo;

    repos = seaf_repo_manager_get_repos_by_owner (seaf->repo_mgr, email);
    ptr = repos;
    while (ptr) {
        r = ptr->data;
        repo = seafile_repo_new ();
        g_object_set (repo, "id", r->id, "name", r->name,
                      "desc", r->desc, "encrypted", r->encrypted, NULL);
        ret = g_list_prepend (ret, repo);
        seaf_repo_unref (r);
        ptr = ptr->next;
    }
    g_list_free (repos);
    ret = g_list_reverse (ret);

    return ret;
}

int
seafile_add_chunk_server (const char *server, GError **error)
{
    SeafCSManager *cs_mgr = seaf->cs_mgr;
    CcnetPeer *peer;

    peer = ccnet_get_peer_by_idname (seaf->ccnetrpc_client, server);
    if (!peer) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid peer id or name %s", server);
        return -1;
    }

    if (seaf_cs_manager_add_chunk_server (cs_mgr, peer->id) < 0) {
        g_object_unref (peer);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_INTERNAL, "Failed to add chunk server %s", server);
        return -1;
    }

    g_object_unref (peer);
    return 0;
}

int
seafile_del_chunk_server (const char *server, GError **error)
{
    SeafCSManager *cs_mgr = seaf->cs_mgr;
    CcnetPeer *peer;

    peer = ccnet_get_peer_by_idname (seaf->ccnetrpc_client, server);
    if (!peer) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid peer id or name %s", server);
        return -1;
    }

    if (seaf_cs_manager_del_chunk_server (cs_mgr, peer->id) < 0) {
        g_object_unref (peer);
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_INTERNAL, "Failed to delete chunk server %s", server);
        return -1;
    }

    g_object_unref (peer);
    return 0;
}

char *
seafile_list_chunk_servers (GError **error)
{
    SeafCSManager *cs_mgr = seaf->cs_mgr;
    GList *servers, *ptr;
    char *cs_id;
    CcnetPeer *peer;
    GString *buf = g_string_new ("");

    servers = seaf_cs_manager_get_chunk_servers (cs_mgr);
    ptr = servers;
    while (ptr) {
        cs_id = ptr->data;
        peer = ccnet_get_peer (seaf->ccnetrpc_client, cs_id);
        if (!peer) {
            g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_INTERNAL, "Internal error");
            g_string_free (buf, TRUE);
            return NULL;
        }
        g_object_unref (peer);

        g_string_append_printf (buf, "%s\n", cs_id);
        ptr = ptr->next;
    }
    g_list_free (servers);

    return (g_string_free (buf, FALSE));
}

int
seafile_set_monitor (const char *monitor_id, GError **error)
{
    CcnetPeer *peer;

    peer = ccnet_get_peer (seaf->ccnetrpc_client, monitor_id);
    if (!peer) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Invalid peer id %s",
                     monitor_id);
        return -1;
    }
    g_object_unref (peer);

    if (seafile_session_set_monitor (seaf, monitor_id) < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_INTERNAL, "Failed to set monitor to %s",
                     monitor_id);
        return -1;
    }

    return 0;
}

char *
seafile_get_monitor (GError **error)
{
    return g_strdup (seaf->monitor_id);
}

gint64
seafile_get_user_quota_usage (const char *email, GError **error)
{
    gint64 ret;

    if (!email) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Bad user id");
        return -1;
    }

    ret = get_user_quota_usage (seaf, email);
    if (ret < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, "Internal server error");
        return -1;
    }

    return ret;
}

gint64
seafile_get_org_quota_usage (int org_id, GError **error)
{
    gint64 ret;

    ret = get_org_quota_usage (seaf, org_id);
    if (ret < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, "Internal server error");
        return -1;
    }

    return ret;
}

gint64
seafile_get_org_user_quota_usage (int org_id, const char *user, GError **error)
{
    gint64 ret;

    if (!user) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Bad user id");
        return -1;
    }

    ret = get_org_user_quota_usage (seaf, org_id, user);
    if (ret < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, "Internal server error");
        return -1;
    }

    return ret;
}

gint64
seafile_server_repo_size(const char *repo_id, GError **error)
{
    gint64 ret;

    if (!repo_id || strlen(repo_id) != 36) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Bad repo id");
        return -1;
    }

    ret = seaf_repo_manager_get_repo_size (seaf->repo_mgr, repo_id);
    if (ret < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, "Internal server error");
        return -1;
    }

    return ret;
}

int
seafile_repo_set_access_property (const char *repo_id, const char *ap, GError **error)
{
    int ret;

    if (!repo_id) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return -1;
    }

    if (strlen(repo_id) != 36) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Wrong repo id");
        return -1;
    }

    if (g_strcmp0(ap, "public") != 0 && g_strcmp0(ap, "own") != 0 && g_strcmp0(ap, "private") != 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Wrong access property");
        return -1;
    }

    ret = seaf_repo_manager_set_access_property (seaf->repo_mgr, repo_id, ap);
    if (ret < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, "Internal server error");
        return -1;
    }

    return ret;
}

char *
seafile_repo_query_access_property (const char *repo_id, GError **error)
{
    char *ret;

    if (!repo_id) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return NULL;
    }

    if (strlen(repo_id) != 36) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Wrong repo id");
        return NULL;
    }

    ret = seaf_repo_manager_query_access_property (seaf->repo_mgr, repo_id);

    return ret;
}

char *
seafile_web_get_access_token (const char *repo_id,
                              const char *obj_id,
                              const char *op,
                              const char *username,
                              GError **error)
{
    char *token;

    if (!repo_id || !obj_id || !op || !username) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Missing args");
        return NULL;
    }

    token = seaf_web_at_manager_get_access_token (seaf->web_at_mgr,
                                                  repo_id, obj_id, op, username);
    return token;
}

GObject *
seafile_web_query_access_token (const char *token, GError **error)
{
    SeafileWebAccess *webaccess = NULL;

    if (!token) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Token should not be null");
        return NULL;
    }

    webaccess = seaf_web_at_manager_query_access_token (seaf->web_at_mgr,
                                                        token);
    if (webaccess)
        return (GObject *)webaccess;

    return NULL;
}

int
seafile_add_share (const char *repo_id, const char *from_email,
                   const char *to_email, const char *permission, GError **error)
{
    int ret;

    if (!repo_id || !from_email || !to_email || !permission) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Missing args");
        return -1;
    }

    if (g_strcmp0 (from_email, to_email) == 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Can not share repo to myself");
        return -1;
    }

    ret = seaf_share_manager_add_share (seaf->share_mgr, repo_id, from_email,
                                        to_email, permission);

    return ret;
}

GList *
seafile_list_share_repos (const char *email, const char *type,
                          int start, int limit, GError **error)
{
    if (g_strcmp0 (type, "from_email") != 0 &&
        g_strcmp0 (type, "to_email") != 0 ) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Wrong type argument");
        return NULL;
    }

    return seaf_share_manager_list_share_repos (seaf->share_mgr,
                                                email, type,
                                                start, limit);
}

GList *
seafile_list_org_share_repos (int org_id, const char *email, const char *type,
                              int start, int limit, GError **error)
{
    if (g_strcmp0 (type, "from_email") != 0 &&
        g_strcmp0 (type, "to_email") != 0 ) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Wrong type argument");
        return NULL;
    }

    return seaf_share_manager_list_org_share_repos (seaf->share_mgr,
                                                    org_id, email, type,
                                                    start, limit);
}

int
seafile_remove_share (const char *repo_id, const char *from_email,
                      const char *to_email, GError **error)
{
    int ret;

    if (!repo_id || !from_email ||!to_email) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Missing args");
        return -1;
    }

    ret = seaf_share_manager_remove_share (seaf->share_mgr, repo_id, from_email,
                                           to_email);

    return ret;
}

/* Group repo RPC. */

int
seafile_group_share_repo (const char *repo_id, int group_id,
                          const char *user_name, const char *permission,
                          GError **error)
{
    SeafRepoManager *mgr = seaf->repo_mgr;
    int ret;

    if (group_id <= 0 || !user_name || !repo_id || !permission) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Bad input argument");
        return -1;
    }

    ret = seaf_repo_manager_add_group_repo (mgr, repo_id, group_id, user_name,
                                            permission, error);

    return ret;
}

int
seafile_group_unshare_repo (const char *repo_id, int group_id,
                            const char *user_name, GError **error)
{
    SeafRepoManager *mgr = seaf->repo_mgr;
    int ret;

    if (!user_name || !repo_id) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "User name and repo id can not be NULL");
        return -1;
    }

    ret = seaf_repo_manager_del_group_repo (mgr, repo_id, group_id, error);

    return ret;

}

char *
seafile_get_shared_groups_by_repo(const char *repo_id, GError **error)
{
    SeafRepoManager *mgr = seaf->repo_mgr;
    GList *group_ids = NULL, *ptr;
    GString *result;
    
    if (!repo_id) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Bad arguments");
        return NULL;
    }

    group_ids = seaf_repo_manager_get_groups_by_repo (mgr, repo_id, error);
    if (!group_ids) {
        return NULL;
    }

    result = g_string_new("");
    ptr = group_ids;
    while (ptr) {
        g_string_append_printf (result, "%d\n", (int)(long)ptr->data);
        ptr = ptr->next;
    }
    g_list_free (group_ids);

    return g_string_free (result, FALSE);
}

char *
seafile_get_group_repoids (int group_id, GError **error)
{
    SeafRepoManager *mgr = seaf->repo_mgr;
    GList *repo_ids = NULL, *ptr;
    GString *result;

    repo_ids = seaf_repo_manager_get_group_repoids (mgr, group_id, error);
    if (!repo_ids) {
        return NULL;
    }

    result = g_string_new("");
    ptr = repo_ids;
    while (ptr) {
        g_string_append_printf (result, "%s\n", (char *)ptr->data);
        g_free (ptr->data);
        ptr = ptr->next;
    }
    g_list_free (repo_ids);

    return g_string_free (result, FALSE);
}

GList *
seafile_get_group_repos_by_owner (char *user, GError **error)
{
    SeafRepoManager *mgr = seaf->repo_mgr;
    GList *ret = NULL;

    if (!user) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "user name can not be NULL");
        return NULL;
    }

    ret = seaf_repo_manager_get_group_repos_by_owner (mgr, user, error);
    if (!ret) {
        return NULL;
    }

    return g_list_reverse (ret);
}

char *
seafile_get_group_repo_owner (const char *repo_id, GError **error)
{
    SeafRepoManager *mgr = seaf->repo_mgr;
    GString *result = g_string_new ("");

    char *share_from = seaf_repo_manager_get_group_repo_owner (mgr, repo_id,
                                                               error);
    if (share_from) {
        g_string_append_printf (result, "%s", share_from);
        g_free (share_from);
    }

    return g_string_free (result, FALSE);
}

int
seafile_remove_repo_group(int group_id, const char *username, GError **error)
{
    if (group_id <= 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Wrong group id argument");
        return -1;
    }

    return seaf_repo_manager_remove_group_repos (seaf->repo_mgr,
                                                 group_id, username,
                                                 error);
}

/* Inner public repo RPC */

int
seafile_set_inner_pub_repo (const char *repo_id,
                            const char *permission,
                            GError **error)
{
    if (!repo_id) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Bad args");
        return -1;
    }

    if (seaf_repo_manager_set_inner_pub_repo (seaf->repo_mgr,
                                              repo_id, permission) < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, "Internal error");
        return -1;
    }

    return 0;
}

int
seafile_unset_inner_pub_repo (const char *repo_id, GError **error)
{
    if (!repo_id) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Bad args");
        return -1;
    }

    if (seaf_repo_manager_unset_inner_pub_repo (seaf->repo_mgr, repo_id) < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, "Internal error");
        return -1;
    }

    return 0;
}

GList *
seafile_list_inner_pub_repos (GError **error)
{
    return seaf_repo_manager_list_inner_pub_repos (seaf->repo_mgr);
}

GList *
seafile_list_inner_pub_repos_by_owner (const char *user, GError **error)
{
    if (!user) {
        g_set_error (error, 0, SEAF_ERR_BAD_ARGS, "Bad arguments");
        return NULL;
    }

    return seaf_repo_manager_list_inner_pub_repos_by_owner (seaf->repo_mgr, user);
}

int
seafile_is_inner_pub_repo (const char *repo_id, GError **error)
{
    if (!repo_id) {
        g_set_error (error, 0, SEAF_ERR_BAD_ARGS, "Bad arguments");
        return -1;
    }

    return seaf_repo_manager_is_inner_pub_repo (seaf->repo_mgr, repo_id);
}

/* Org Repo RPC. */

GList *
seafile_get_org_repo_list (int org_id, int start, int limit, GError **error)
{
    GList *repos = NULL;
    GList *ret = NULL;

    if (org_id < 0 || start < 0 || limit < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Bad args");
        return NULL;
    }

    repos = seaf_repo_manager_get_org_repo_list (seaf->repo_mgr, org_id,
                                                 start ,limit);
    ret = convert_repo_list (repos);

    GList *ptr;
    for (ptr = repos; ptr != NULL; ptr = ptr->next)
        seaf_repo_unref ((SeafRepo *)ptr->data);

    g_list_free (repos);

    return ret;
}

int
seafile_remove_org_repo_by_org_id (int org_id, GError **error)
{
    if (org_id < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Bad args");
        return -1;
    }

    return seaf_repo_manager_remove_org_repo_by_org_id (seaf->repo_mgr, org_id);
}

/* Org Group Repo RPC. */

int
seafile_add_org_group_repo (const char *repo_id,
                            int org_id,
                            int group_id,
                            const char *owner,
                            const char *permission,
                            GError **error)
{
    if (!repo_id || !owner || org_id < 0 || group_id < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Bad args");
        return -1;
    }

    return seaf_repo_manager_add_org_group_repo (seaf->repo_mgr,
                                                 repo_id,
                                                 org_id,
                                                 group_id,
                                                 owner,
                                                 permission,
                                                 error);
}

int
seafile_del_org_group_repo (const char *repo_id,
                            int org_id,
                            int group_id,
                            GError **error)
{
    if (!repo_id || org_id < 0 || group_id < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Bad args");
        return -1;
    }

    return seaf_repo_manager_del_org_group_repo (seaf->repo_mgr,
                                                 repo_id,
                                                 org_id,
                                                 group_id,
                                                 error);
}

char *
seafile_get_org_group_repoids (int org_id, int group_id, GError **error)
{
    SeafRepoManager *mgr = seaf->repo_mgr;
    GList *repo_ids = NULL, *ptr;
    GString *result;

    if (org_id < 0 || group_id < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Bad args");
        return NULL;
    }
    
    repo_ids = seaf_repo_manager_get_org_group_repoids (mgr, org_id, group_id,
                                                        error);
    if (!repo_ids) {
        return NULL;
    }

    result = g_string_new("");
    ptr = repo_ids;
    while (ptr) {
        g_string_append_printf (result, "%s\n", (char *)ptr->data);
        g_free (ptr->data);
        ptr = ptr->next;
    }
    g_list_free (repo_ids);

    return g_string_free (result, FALSE);
}

char *
seafile_get_org_group_repo_owner (int org_id, int group_id,
                                  const char *repo_id, GError **error)
{
    SeafRepoManager *mgr = seaf->repo_mgr;
    GString *result = g_string_new ("");

    char *owner = seaf_repo_manager_get_org_group_repo_owner (mgr, org_id,
                                                              group_id,
                                                              repo_id, error);
    if (owner) {
        g_string_append_printf (result, "%s", owner);
        g_free (owner);
    }

    return g_string_free (result, FALSE);
    
}

GList *
seafile_get_org_group_repos_by_owner (int org_id, const char *user,
                                      GError **error)
{
    SeafRepoManager *mgr = seaf->repo_mgr;
    GList *ret = NULL;

    if (!user || org_id < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Bad arguments");
        return NULL;
    }

    ret = seaf_repo_manager_get_org_group_repos_by_owner (mgr, org_id, user,
                                                          error);
    if (!ret) {
        return NULL;
    }

    return g_list_reverse (ret);
}

char *
seafile_get_org_groups_by_repo (int org_id, const char *repo_id,
                                GError **error)
{
    SeafRepoManager *mgr = seaf->repo_mgr;
    GList *group_ids = NULL, *ptr;
    GString *result;
    
    if (!repo_id || org_id < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Bad arguments");
        return NULL;
    }

    group_ids = seaf_repo_manager_get_org_groups_by_repo (mgr, org_id,
                                                          repo_id, error);
    if (!group_ids) {
        return NULL;
    }

    result = g_string_new("");
    ptr = group_ids;
    while (ptr) {
        g_string_append_printf (result, "%d\n", (int)(long)ptr->data);
        ptr = ptr->next;
    }
    g_list_free (group_ids);

    return g_string_free (result, FALSE);
}

/* Org inner public repo RPC */

int
seafile_set_org_inner_pub_repo (int org_id,
                                const char *repo_id,
                                const char *permission,
                                GError **error)
{
    if (!repo_id) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Bad args");
        return -1;
    }

    if (seaf_repo_manager_set_org_inner_pub_repo (seaf->repo_mgr,
                                                  org_id, repo_id,
                                                  permission) < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, "Internal error");
        return -1;
    }

    return 0;
}

int
seafile_unset_org_inner_pub_repo (int org_id, const char *repo_id, GError **error)
{
    if (!repo_id) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Bad args");
        return -1;
    }

    if (seaf_repo_manager_unset_org_inner_pub_repo (seaf->repo_mgr,
                                                    org_id, repo_id) < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL, "Internal error");
        return -1;
    }

    return 0;
}

GList *
seafile_list_org_inner_pub_repos (int org_id, GError **error)
{
    return seaf_repo_manager_list_org_inner_pub_repos (seaf->repo_mgr, org_id);
}

GList *
seafile_list_org_inner_pub_repos_by_owner (int org_id,
                                           const char *user,
                                           GError **error)
{
    if (!user) {
        g_set_error (error, 0, SEAF_ERR_BAD_ARGS, "Bad arguments");
        return NULL;
    }

    return seaf_repo_manager_list_org_inner_pub_repos_by_owner (seaf->repo_mgr,
                                                                org_id, user);
}

gint64
seafile_get_file_size (const char *file_id, GError **error)
{
    gint64 file_size;
    Seafile *file = NULL;

    if (!file_id) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "File id can not be NULL");
        return -1;
    }

    file = seaf_fs_manager_get_seafile (seaf->fs_mgr, file_id);
    if (!file) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_INTERNAL,
                     "Couldn't get file");
        seafile_unref (file);
        return -1;
    }

    file_size = file->file_size;

    seafile_unref (file);
    return file_size;
}

int
seafile_set_passwd (const char *repo_id,
                    const char *user,
                    const char *passwd,
                    GError **error)
{
    if (!repo_id || strlen(repo_id) != 36 || !user || !passwd) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Bad arguments");
        return -1;
    }

    if (seaf_passwd_manager_set_passwd (seaf->passwd_mgr,
                                        repo_id, user, passwd,
                                        error) < 0) {
        return -1;
    }

    return 0;
}

int
seafile_unset_passwd (const char *repo_id,
                      const char *user,
                      GError **error)
{
    if (!repo_id || strlen(repo_id) != 36 || !user) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Bad arguments");
        return -1;
    }

    if (seaf_passwd_manager_unset_passwd (seaf->passwd_mgr,
                                          repo_id, user,
                                          error) < 0) {
        return -1;
    }

    return 0;
}

int
seafile_is_passwd_set (const char *repo_id, const char *user, GError **error)
{
    if (!repo_id || strlen(repo_id) != 36 || !user) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Bad arguments");
        return -1;
    }

    return seaf_passwd_manager_is_passwd_set (seaf->passwd_mgr,
                                              repo_id, user);
}

GObject *
seafile_get_decrypt_key (const char *repo_id, const char *user, GError **error)
{
    SeafileCryptKey *ret;

    if (!repo_id || strlen(repo_id) != 36 || !user) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Bad arguments");
        return NULL;
    }

    ret = seaf_passwd_manager_get_decrypt_key (seaf->passwd_mgr,
                                               repo_id, user);
    if (!ret) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_GENERAL,
                     "Password was not set");
        return NULL;
    }

    return (GObject *)ret;
}

int
seafile_revert_on_server (const char *repo_id,
                          const char *commit_id,
                          const char *user_name,
                          GError **error)
{
    if (!repo_id || strlen(repo_id) != 36 ||
        !commit_id || strlen(commit_id) != 40 ||
        !user_name) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Bad arguments");
        return -1;
    }

    return seaf_repo_manager_revert_on_server (seaf->repo_mgr,
                                               repo_id,
                                               commit_id,
                                               user_name,
                                               error);
}

int
seafile_post_file (const char *repo_id, const char *temp_file_path,
                   const char *parent_dir, const char *file_name,
                   const char *user,
                   GError **error)
{
    if (!repo_id || !temp_file_path || !parent_dir || !file_name || !user) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Argument should not be null");
        return -1;
    }

    if (seaf_repo_manager_post_file (seaf->repo_mgr, repo_id,
                                     temp_file_path, parent_dir,
                                     file_name, user,
                                     error) < 0) {
        return -1;
    }

    return 0;
}

int
seafile_post_multi_files (const char *repo_id,
                          const char *parent_dir,
                          const char *filenames_json,
                          const char *paths_json,
                          const char *user,
                          GError **error)
{
    if (!repo_id || !filenames_json || !parent_dir || !paths_json || !user) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Argument should not be null");
        return -1;
    }

    if (seaf_repo_manager_post_multi_files (seaf->repo_mgr,
                                            repo_id,
                                            parent_dir,
                                            filenames_json,
                                            paths_json,
                                            user,
                                            error) < 0) {
        return -1;
    }

    return 0;
}

int
seafile_put_file (const char *repo_id, const char *temp_file_path,
                  const char *parent_dir, const char *file_name,
                  const char *user, const char *head_id,
                  GError **error)
{
    if (!repo_id || !temp_file_path || !parent_dir || !file_name || !user) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Argument should not be null");
        return -1;
    }

    if (seaf_repo_manager_put_file (seaf->repo_mgr, repo_id,
                                    temp_file_path, parent_dir,
                                    file_name, user, head_id,
                                    error) < 0) {
        return -1;
    }

    return 0;
}

int
seafile_post_dir (const char *repo_id, const char *parent_dir,
                  const char *new_dir_name, const char *user,
                  GError **error)
{
    if (!repo_id || !parent_dir || !new_dir_name || !user) {
        g_set_error (error, 0, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return -1;
    }

    if (seaf_repo_manager_post_dir (seaf->repo_mgr, repo_id,
                                    parent_dir, new_dir_name,
                                    user, error) < 0) {
        return -1;
    }

    return 0;
}

int
seafile_post_empty_file (const char *repo_id, const char *parent_dir,
                         const char *new_file_name, const char *user,
                         GError **error)
{
    if (!repo_id || !parent_dir || !new_file_name || !user) {
        g_set_error (error, 0, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return -1;
    }

    if (seaf_repo_manager_post_empty_file (seaf->repo_mgr, repo_id,
                                           parent_dir, new_file_name,
                                           user, error) < 0) {
        return -1;
    }

    return 0;
}

int
seafile_del_file (const char *repo_id, const char *parent_dir,
                  const char *file_name, const char *user,
                  GError **error)
{
    if (!repo_id || !parent_dir || !file_name || !user) {
        g_set_error (error, 0, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return -1;
    }

    if (seaf_repo_manager_del_file (seaf->repo_mgr, repo_id,
                                    parent_dir, file_name,
                                    user, error) < 0) {
        return -1;
    }

    return 0;
}

int
seafile_copy_file (const char *src_repo_id,
                   const char *src_dir,
                   const char *src_filename,
                   const char *dst_repo_id,
                   const char *dst_dir,
                   const char *dst_filename,
                   const char *user,
                   GError **error)
{
    if (!src_repo_id || !src_dir || !src_filename ||
        !dst_repo_id || !dst_dir || !dst_filename || !user) {
        g_set_error (error, 0, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return -1;
    }

    if (seaf_repo_manager_copy_file (seaf->repo_mgr,
                                     src_repo_id, src_dir, src_filename,
                                     dst_repo_id, dst_dir, dst_filename,
                                     user, error) < 0) {
        return -1;
    }

    return 0;
}

int
seafile_move_file (const char *src_repo_id,
                   const char *src_dir,
                   const char *src_filename,
                   const char *dst_repo_id,
                   const char *dst_dir,
                   const char *dst_filename,
                   const char *user,
                   GError **error)
{
    if (!src_repo_id || !src_dir || !src_filename ||
        !dst_repo_id || !dst_dir || !dst_filename || !user) {
        g_set_error (error, 0, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return -1;
    }

    if (seaf_repo_manager_move_file (seaf->repo_mgr,
                                     src_repo_id, src_dir, src_filename,
                                     dst_repo_id, dst_dir, dst_filename,
                                     user, error) < 0) {
        return -1;
    }

    return 0;
}

int
seafile_rename_file (const char *repo_id,
                     const char *parent_dir,
                     const char *oldname,
                     const char *newname,
                     const char *user,
                     GError **error)
{
    if (!repo_id || !parent_dir || !oldname || !newname || !user) {
        g_set_error (error, 0, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return -1;
    }

    if (seaf_repo_manager_rename_file (seaf->repo_mgr, repo_id,
                                       parent_dir, oldname, newname,
                                       user, error) < 0) {
        return -1;
    }

    return 0;
}

int
seafile_is_valid_filename (const char *repo_id,
                           const char *filename,
                           GError **error)
{
    if (!repo_id || !filename) {
        g_set_error (error, 0, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return -1;
    }

    int ret = seaf_repo_manager_is_valid_filename (seaf->repo_mgr,
                                                   repo_id,
                                                   filename,
                                                   error);
    return ret;
}

char *
seafile_create_repo (const char *repo_name,
                     const char *repo_desc,
                     const char *owner_email,
                     const char *passwd,
                     GError **error)
{
    if (!repo_name || !repo_desc || !owner_email) {
        g_set_error (error, 0, SEAF_ERR_BAD_ARGS, "Argument should not be null");
        return NULL;
    }

    char *repo_id;

    repo_id = seaf_repo_manager_create_new_repo (seaf->repo_mgr,
                                                 repo_name, repo_desc,
                                                 owner_email, passwd,
                                                 error);
    return repo_id;
}

char *
seafile_create_org_repo (const char *repo_name,
                         const char *repo_desc,
                         const char *user,
                         const char *passwd,
                         int org_id,
                         GError **error)
{
    if (!repo_name || !repo_desc || !user || org_id <= 0) {
        g_set_error (error, 0, SEAF_ERR_BAD_ARGS, "Bad arguments");
        return NULL;
    }

    char *repo_id;

    repo_id = seaf_repo_manager_create_org_repo (seaf->repo_mgr,
                                                 repo_name, repo_desc,
                                                 user, passwd,
                                                 org_id, error);
    return repo_id;

}

GList *
seafile_list_org_repos_by_owner (int org_id, const char *user, GError **error)
{
    GList *ret = NULL;
    GList *repos, *ptr;
    SeafRepo *r;
    SeafileRepo *repo;

    repos = seaf_repo_manager_get_org_repos_by_owner (seaf->repo_mgr, org_id,
                                                      user);
    ptr = repos;
    while (ptr) {
        r = ptr->data;
        repo = seafile_repo_new ();
        g_object_set (repo, "id", r->id, "name", r->name,
                      "desc", r->desc, "encrypted", r->encrypted, NULL);
        ret = g_list_prepend (ret, repo);
        seaf_repo_unref (r);
        ptr = ptr->next;
    }
    g_list_free (repos);
    ret = g_list_reverse (ret);

    return ret;
}

char *
seafile_get_org_repo_owner (const char *repo_id, GError **error)
{
    SeafRepoManager *mgr = seaf->repo_mgr;
    GString *result = g_string_new ("");

    char *owner = seaf_repo_manager_get_org_repo_owner (mgr, repo_id);
    if (owner) {
        g_string_append_printf (result, "%s", owner);
        g_free (owner);
    }

    return g_string_free (result, FALSE);
}

int
seafile_get_org_id_by_repo_id (const char *repo_id, GError **error)
{
    if (!repo_id) {
        g_set_error (error, 0, SEAF_ERR_BAD_ARGS, "Bad arguments");
        return -1;
    }

    return seaf_repo_manager_get_org_id_by_repo_id (seaf->repo_mgr, repo_id,
                                                    error);
}

int
seafile_set_user_quota (const char *user, gint64 quota, GError **error)
{
    if (!user) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Bad arguments");
        return -1;
    }

    return seaf_quota_manager_set_user_quota (seaf->quota_mgr, user, quota);
}

gint64
seafile_get_user_quota (const char *user, GError **error)
{
    if (!user) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Bad arguments");
        return -1;
    }

    return seaf_quota_manager_get_user_quota (seaf->quota_mgr, user);
}

int
seafile_set_org_quota (int org_id, gint64 quota, GError **error)
{
    return seaf_quota_manager_set_org_quota (seaf->quota_mgr, org_id, quota);
}

gint64
seafile_get_org_quota (int org_id, GError **error)
{
    return seaf_quota_manager_get_org_quota (seaf->quota_mgr, org_id);
}

int
seafile_set_org_user_quota (int org_id, const char *user, gint64 quota, GError **error)
{
    if (!user) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Bad arguments");
        return -1;
    }

    return seaf_quota_manager_set_org_user_quota (seaf->quota_mgr,
                                                  org_id, user, quota);
}

gint64
seafile_get_org_user_quota (int org_id, const char *user, GError **error)
{
    if (!user) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Bad arguments");
        return -1;
    }

    return seaf_quota_manager_get_org_user_quota (seaf->quota_mgr, org_id, user);
}

int
seafile_check_quota (const char *repo_id, GError **error)
{
    if (!repo_id) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Bad arguments");
        return -1;
    }

    return seaf_quota_manager_check_quota (seaf->quota_mgr, repo_id);
}

char *
seafile_get_file_by_path (const char *repo_id, const char *path,
                          GError **error)
{
    SeafRepo *repo = NULL;
    SeafCommit *commit = NULL;
    char *file_id = NULL;

    if (!repo_id || !path) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Bad arguments");
        return NULL;
    }

    repo = seaf_repo_manager_get_repo (seaf->repo_mgr, repo_id);
    if (!repo) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_INTERNAL,
                     "Get repo error");
        goto out;
    }

    commit = seaf_commit_manager_get_commit (seaf->commit_mgr,
                                             repo->head->commit_id);
    if (!commit) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_INTERNAL,
                     "Get commit error");
        goto out;
    }

    file_id = seaf_fs_manager_path_to_obj_id (seaf->fs_mgr, commit->root_id,
                                               path, NULL, error);

out:
    if (repo)
        seaf_repo_unref (repo);
    if (commit)
        seaf_commit_unref (commit);
    return file_id;
}

GList *
seafile_list_file_revisions (const char *repo_id,
                             const char *path,
                             int limit,
                             GError **error)
{
    if (!repo_id || !path) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Bad arguments");
        return NULL;
    }

    GList *commit_list;
    commit_list = seaf_repo_manager_list_file_revisions (seaf->repo_mgr,
                                                         repo_id, path,
                                                         limit, error);
    GList *l = NULL;
    if (commit_list) {
        GList *p;
        for (p = commit_list; p; p = p->next) {
            SeafCommit *commit = p->data;
            SeafileCommit *c = convert_to_seafile_commit(commit);
            l = g_list_prepend (l, c);
            seaf_commit_unref (commit);
        }
        g_list_free (commit_list);
        l = g_list_reverse (l);
    }

    return l;
}

int
seafile_revert_file (const char *repo_id,
                     const char *commit_id,
                     const char *path,
                     const char *user,
                     GError **error)
{
    if (!repo_id || !commit_id || !path || !user) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Bad arguments");
        return -1;
    }

    return seaf_repo_manager_revert_file (seaf->repo_mgr,
                                          repo_id, commit_id,
                                          path, user, error);
}

int
seafile_revert_dir (const char *repo_id,
                    const char *commit_id,
                    const char *path,
                    const char *user,
                    GError **error)
{
    if (!repo_id || !commit_id || !path || !user) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Bad arguments");
        return -1;
    }

    return seaf_repo_manager_revert_dir (seaf->repo_mgr,
                                         repo_id, commit_id,
                                         path, user, error);
}

GList *
seafile_get_deleted (const char *repo_id, GError **error)
{
    if (!repo_id) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Bad arguments");
        return NULL;
    }

    return seaf_repo_manager_get_deleted_entries (seaf->repo_mgr, repo_id, error);
}

int
seafile_set_repo_token (const char *repo_id,
                        const char *email,
                        const char *token,
                        GError **error)
{
    int ret;

    if (!repo_id || !email || !token) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Arguments should not be empty");
        return -1;
    }

    if (!seaf_repo_manager_repo_exists (seaf->repo_mgr, repo_id)) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_REPO, "Repo %s doesn't exist", repo_id);
        return -1;
    }

    ret = seaf_repo_manager_set_repo_token (seaf->repo_mgr,
                                            repo_id, email, token);
    if (ret < 0) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_INTERNAL,
                     "Failed to set token for repo %s", repo_id);
        return -1;
    }

    return 0;
}

char *
seafile_get_repo_token_nonnull (const char *repo_id,
                                const char *email,
                                GError **error)
{
    char *token;

    if (!repo_id || !email) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Arguments should not be empty");
        return NULL;
    }

    token = seaf_repo_manager_get_repo_token_nonnull (seaf->repo_mgr, repo_id, email);

    return token;
}

char *
seafile_check_permission (const char *repo_id, const char *user, GError **error)
{
    if (!repo_id || !user) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Arguments should not be empty");
        return NULL;
    }

    return seaf_repo_manager_check_permission (seaf->repo_mgr,
                                               repo_id, user, error);
}

int
seafile_set_share_permission (const char *repo_id,
                              const char *from_email,
                              const char *to_email,
                              const char *permission,
                              GError **error)
{
    if (!repo_id || !from_email || !to_email || !permission) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Arguments should not be empty");
        return -1;
    }

    return seaf_share_manager_set_permission (seaf->share_mgr,
                                              repo_id,
                                              from_email,
                                              to_email,
                                              permission);
}

int
seafile_set_group_repo_permission (int group_id,
                                   const char *repo_id,
                                   const char *permission,
                                   GError **error)
{
    if (!repo_id || !permission) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Arguments should not be empty");
        return -1;
    }

    return seaf_repo_manager_set_group_repo_perm (seaf->repo_mgr,
                                                  repo_id,
                                                  group_id,
                                                  permission,
                                                  error);
}

int
seafile_set_org_group_repo_permission (int org_id,
                                       int group_id,
                                       const char *repo_id,
                                       const char *permission,
                                       GError **error)
{
    if (!repo_id || !permission) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS, "Arguments should not be empty");
        return -1;
    }

    return seaf_repo_manager_set_org_group_repo_perm (seaf->repo_mgr,
                                                      repo_id,
                                                      org_id,
                                                      group_id,
                                                      permission,
                                                      error);
}

char *
seafile_get_file_id_by_commit_and_path(const char *commit_id,
                                       const char *path,
                                       GError **error)
{
    SeafCommit *commit;
    char *file_id;

    if (!commit_id || !path) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "Arguments should not be empty");
        return NULL;
    }

    commit = seaf_commit_manager_get_commit(seaf->commit_mgr, commit_id);
    if (!commit) {
        g_set_error (error, SEAFILE_DOMAIN, SEAF_ERR_BAD_ARGS,
                     "bad commit id");
        return NULL;
    }

    file_id = seaf_fs_manager_path_to_obj_id (seaf->fs_mgr,
                        commit->root_id, path, NULL, error);

    seaf_commit_unref(commit);

    return file_id;
}

#endif  /* SEAFILE_SERVER */
