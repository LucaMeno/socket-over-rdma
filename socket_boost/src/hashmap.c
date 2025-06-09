
#include "hashmap.h"

void add_or_update_hash_entry(sock_hash_entry_t **sock_hash, struct sock_id app_sk_id, int fd)
{
    sock_hash_entry_t *entry = NULL;
    HASH_FIND(hh, *sock_hash, &app_sk_id, sizeof(struct sock_id), entry);
    if (entry)
    {
        entry->proxy_fd = fd;
    }
    else
    {
        entry = malloc(sizeof(*entry));
        if (!entry)
        {
            perror("malloc");
            exit(EXIT_FAILURE);
        }
        memset(entry, 0, sizeof(*entry));
        entry->app_sk_id = app_sk_id;
        entry->proxy_fd = fd;
        HASH_ADD(hh, *sock_hash, app_sk_id, sizeof(struct sock_id), entry);
    }
}

sock_hash_entry_t *find_hash_entry(sock_hash_entry_t **sock_hash, struct sock_id app_sk_id)
{
    sock_hash_entry_t *entry = NULL;
    HASH_FIND(hh, *sock_hash, &app_sk_id, sizeof(struct sock_id), entry);
    return entry;
}

void free_hash_entry(sock_hash_entry_t **sock_hash)
{
    struct sock_hash_entry *cur, *tmp;
    HASH_ITER(hh, *sock_hash, cur, tmp)
    {
        HASH_DEL(*sock_hash, cur);
        free(cur);
    }
}