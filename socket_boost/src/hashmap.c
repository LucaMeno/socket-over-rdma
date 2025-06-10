
#include "hashmap.h"

void add_or_update_hash_entry(sockid_fd_entry_t **sock_hash, entry_key_t key, entry_key_t val);
void remove_hash_entry(sockid_fd_entry_t **sock_hash, entry_key_t key);
sockid_fd_entry_t *find_hash_entry(sockid_fd_entry_t *sock_hash, entry_key_t key);

/* ADD / UPDATE */

#include "hashmap.h"

/* ADD / UPDATE */

void hash_add_update_sk_to_fd(sockid_fd_entry_t **sock_hash, sock_id_t app_sk_id, int fd)
{
    entry_key_t key = {0};
    key.sk_id = app_sk_id;

    entry_key_t val = {0};
    val.fd = fd;

    add_or_update_hash_entry(sock_hash, key, val);
    add_or_update_hash_entry(sock_hash, val, key); // Also add reverse mapping
}

void hash_add_update_fd_to_sk(sockid_fd_entry_t **sock_hash, int fd, sock_id_t app_sk_id)
{
    entry_key_t key = {0};
    key.fd = fd;

    entry_key_t val = {0};
    val.sk_id = app_sk_id;

    add_or_update_hash_entry(sock_hash, key, val);
    add_or_update_hash_entry(sock_hash, val, key); // Also add reverse mapping
}

void add_or_update_hash_entry(sockid_fd_entry_t **sock_hash, entry_key_t key, entry_key_t val)
{
    sockid_fd_entry_t *entry = NULL;
    HASH_FIND(hh, *sock_hash, &key, sizeof(entry_key_t), entry);
    if (entry)
    {
        entry->val = val;
    }
    else
    {
        entry = malloc(sizeof(sockid_fd_entry_t));
        if (!entry)
        {
            perror("malloc");
            exit(EXIT_FAILURE);
        }
        memset(entry, 0, sizeof(sockid_fd_entry_t));
        entry->key = key;
        entry->val = val;
        HASH_ADD(hh, *sock_hash, key, sizeof(entry_key_t), entry);
    }
}

/* REMOVE */

void hash_remove_fd_to_sk(sockid_fd_entry_t **sock_hash, int fd)
{
    entry_key_t key = {0};
    key.fd = fd;
    remove_hash_entry(sock_hash, key);
}

void hash_remove_sk_to_fd(sockid_fd_entry_t **sock_hash, sock_id_t app_sk_id)
{
    entry_key_t key = {0};
    key.sk_id = app_sk_id;
    remove_hash_entry(sock_hash, key);
}

void remove_hash_entry(sockid_fd_entry_t **sock_hash, entry_key_t key)
{
    sockid_fd_entry_t *entry = NULL;
    HASH_FIND(hh, *sock_hash, &key, sizeof(entry_key_t), entry);
    if (entry)
    {
        HASH_DEL(*sock_hash, entry);
        free(entry);
    }
}

/* GET */

int hash_get_fd_from_sk(sockid_fd_entry_t *sock_hash, sock_id_t app_sk_id)
{
    entry_key_t key = {0};
    key.sk_id = app_sk_id;

    sockid_fd_entry_t *entry = find_hash_entry(sock_hash, key);
    if (entry)
        return entry->val.fd;

    return -1; // Not found
}

sock_id_t *hash_get_sk_from_fd(sockid_fd_entry_t *sock_hash, int fd)
{
    entry_key_t key = {0};
    key.fd = fd;

    sockid_fd_entry_t *entry = find_hash_entry(sock_hash, key);
    if (entry)
        return &entry->val.sk_id;

    return NULL; // Not found
}

sockid_fd_entry_t *find_hash_entry(sockid_fd_entry_t *sock_hash, entry_key_t key)
{
    sockid_fd_entry_t *entry = NULL;
    HASH_FIND(hh, sock_hash, &key, sizeof(entry_key_t), entry);
    return entry;
}

/* CLEANUP */

void free_hash_entry(sockid_fd_entry_t **sock_hash)
{
    sockid_fd_entry_t *cur, *tmp;
    HASH_ITER(hh, *sock_hash, cur, tmp)
    {
        HASH_DEL(*sock_hash, cur);
        free(cur);
    }
}
