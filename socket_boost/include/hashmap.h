
#ifndef HASHMAP_H
#define HASHMAP_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "uthash.h"
#include "common.h"

typedef struct entry sockid_fd_entry_t;
typedef struct key entry_key_t;

struct key
{
    sock_id_t sk_id;
    int fd;
};

struct entry
{
    entry_key_t key;
    entry_key_t val;
    UT_hash_handle hh; // makes this structure hashable
};

void hash_add_update_sk_to_fd(sockid_fd_entry_t **sock_hash, sock_id_t app_sk_id, int fd);
void hash_add_update_fd_to_sk(sockid_fd_entry_t **sock_hash, int fd, sock_id_t app_sk_id);

void hash_remove_fd_to_sk(sockid_fd_entry_t **sock_hash, int fd);
void hash_remove_sk_to_fd(sockid_fd_entry_t **sock_hash, sock_id_t app_sk_id);

int hash_get_fd_from_sk(sockid_fd_entry_t *sock_hash, sock_id_t app_sk_id);
sock_id_t* hash_get_sk_from_fd(sockid_fd_entry_t *sock_hash, int fd);

void free_hash_entry(sockid_fd_entry_t **sock_hash);

#endif // HASHMAP_H