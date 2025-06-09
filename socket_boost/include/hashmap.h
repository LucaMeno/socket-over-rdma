
#ifndef HASHMAP_H
#define HASHMAP_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "uthash.h"
#include "common.h"

typedef struct sock_hash_entry sock_hash_entry_t;

struct sock_hash_entry
{
    struct sock_id app_sk_id;
    int proxy_fd;
    UT_hash_handle hh; // makes this structure hashable
};

void add_or_update_hash_entry(sock_hash_entry_t **sock_hash, struct sock_id app_sk_id, int fd);

sock_hash_entry_t *find_hash_entry(sock_hash_entry_t **sock_hash, struct sock_id app_sk_id);

void free_hash_entry(sock_hash_entry_t **sock_hash);

#endif // HASHMAP_H