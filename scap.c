#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define CGROUP_PATH "/sys/fs/cgroup"
#define MAP_PATH "/sys/fs/bpf/mysoc"
#define BUFFER_SIZE 2048
#define PORT 5556

int main(int argc, char **argv)
{
    struct bpf_object *obj;

    // open the BPF object file
    obj = bpf_object__open_file("scap.bpf.o", NULL);
    if (!obj)
    {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    // load the BPF object file into the kernel
    int err = bpf_object__load(obj);
    if (err)
    {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        return 1;
    }

    struct bpf_map *sockmap, *mysoc;

    // find the sockmap in the object file
    sockmap = bpf_object__find_map_by_name(obj, "sockmap");
    if (!sockmap)
    {
        fprintf(stderr, "Failed to find the sockmap\n");
        return -1;
    }

    // find the mysoc map in the object file
    mysoc = bpf_object__find_map_by_name(obj, "mysoc");
    if (!mysoc)
    {
        fprintf(stderr, "Failed to find the mysoc map\n");
        return -1;
    }

    // get the file descriptor for the map
    int sockmap_fd, mysoc_fd;
    sockmap_fd = bpf_map__fd(sockmap);
    if (sockmap_fd < 0)
    {
        fprintf(stderr, "Failed to get map fd\n");
        return -1;
    }

    mysoc_fd = bpf_map__fd(mysoc);
    if(mysoc_fd < 0) {
        fprintf(stderr, "Failed to get map sock fd\n");
        return -1;
    }

    struct bpf_program *prog_sockops, *prog_sk_msg;
    int prog_fd_sockops, prog_fd_sk_msg;

    // find the programs in the object file
    prog_sockops = bpf_object__find_program_by_name(obj, "sockops_prog");
    prog_fd_sockops = bpf_program__fd(prog_sockops);

    prog_sk_msg = bpf_object__find_program_by_name(obj, "sk_msg_prog");
    prog_fd_sk_msg = bpf_program__fd(prog_sk_msg);

    // get the file descriptor for the cgroup
    int cgroup_fd = open(CGROUP_PATH, O_RDONLY);
    if (cgroup_fd < 0)
    {
        fprintf(stderr, "Failed to open cgroup: %s\n", strerror(errno));
        return 1;
    }

    // attach sockops_prog to the cgroup
    err = bpf_prog_attach(prog_fd_sockops, cgroup_fd, BPF_CGROUP_SOCK_OPS, 0);
    if (err < 0)
    {
        fprintf(stderr, "Failed to attach sockops_prog to cgroup: %d\n", err);
        return 1;
    }

    // Attach sk_msg_prog to the sockmap
    err = bpf_prog_attach(prog_fd_sk_msg, sockmap_fd, BPF_SK_MSG_VERDICT, 0);
    if (err < 0)
    {
        fprintf(stderr, "Failed to attach sk_msg_prog to sockmap: %d\n", err);
        return 1;
    }

    printf("eBPF program is running\n");

    // wait for user input before exiting
    /*printf("Press Enter to exit...\n");
    getchar();*/

    /*--------- PROXY ------------*/

    int sock;
    struct sockaddr_in server_addr;
    
    // Creazione del socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Errore nella creazione del socket");
        return 1;
    }

    // Configurazione dell'indirizzo del server
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(PORT);  // Porta di ascolto

    // Bind del socket all'indirizzo e porta
    if (bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Errore nel bind del socket");
        close(sock);
        return 1;
    }

    // Mettiamo il socket in ascolto
    if (listen(sock, 5) < 0) {
        perror("listen error");
        close(sock);
        return 1;
    }

    printf("Waiting for client...\n");

    // Accettiamo un client
    int client_sock = accept(sock, NULL, NULL);
    if (client_sock < 0) {
        perror("Accept error");
        close(sock);
        return 1;
    }

    printf("Client connected.\n");

    // Chiave per la mappa SOCKHASH (può essere un ID del socket)
    int key = 0;

    // Inseriamo il socket nella mappa SOCKHASH
    if (bpf_map_update_elem(mysoc_fd, &key, &client_sock, BPF_ANY) < 0) {
        perror("Errore nell'inserimento del socket nella mappa BPF");
        close(client_sock);
        close(sock);
    }

    printf("Socket aggiunto alla mappa SOCKHASH.\n");

    // Riceviamo dati dal socket
    char buffer[BUFFER_SIZE] = {0};
    printf("Waiting for data...\n");
    while (1) {
        ssize_t bytes_received = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes_received <= 0) {
            perror("Errore nella ricezione o connessione chiusa");
            break;
        }
        buffer[bytes_received] = '\0';
        printf("Messaggio ricevuto: %s\n", buffer);
    }

    /*---------- CLOSE ------------*/

    close(client_sock);
    close(sock);

    // detach the programs from the cgroup
    err = bpf_prog_detach(cgroup_fd, BPF_CGROUP_SOCK_OPS);
    if (err < 0)
    {
        fprintf(stderr, "Failed to detach sockops_prog from cgroup: %d\n", err);
        return 1;
    }

    printf("Successfully detached eBPF program!\n");

    return 0;
}
