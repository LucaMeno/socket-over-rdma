#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>

#define MAP_PATH "/sys/fs/bpf/mysoc"
#define BUFFER_SIZE 2048
#define PORT 5555

int main() {
    int sock, map_fd;
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

    // Apriamo la mappa BPF
    map_fd = bpf_obj_get(MAP_PATH);
    if (map_fd < 0) {
        perror("Errore nell'apertura della mappa BPF");
        close(client_sock);
        close(sock);
        return 1;
    }

    // Chiave per la mappa SOCKHASH (può essere un ID del socket)
    int key = client_sock;

    // Inseriamo il socket nella mappa SOCKHASH
    if (bpf_map_update_elem(map_fd, &key, &client_sock, BPF_ANY) < 0) {
        perror("Errore nell'inserimento del socket nella mappa BPF");
        close(client_sock);
        close(sock);
        return 1;
    }

    printf("Socket aggiunto alla mappa SOCKHASH.\n");

    // Riceviamo dati dal socket
    char buffer[1024];
    while (1) {
        ssize_t bytes_received = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes_received <= 0) {
            perror("Errore nella ricezione o connessione chiusa");
            break;
        }
        buffer[bytes_received] = '\0';
        printf("Messaggio ricevuto: %s\n", buffer);
    }

    // Pulizia
    close(client_sock);
    close(sock);
    return 0;
}




/*
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 7777
#define BUFFER_SIZE 1024

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};

    // Create socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Bind the socket to the port
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    // Start listening for connections
    if (listen(server_fd, 3) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Server is listening on port %d...\n", PORT);

    // Accept client connection
    if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
        perror("Accept failed");
        exit(EXIT_FAILURE);
    }

    printf("Client connected.\n");

    
    while(1) {
        read(new_socket, buffer, BUFFER_SIZE);
        if (strcmp(buffer, "STOP") == 0) {
            break;
        }
        //send(new_socket, buffer, strlen(buffer), 0);
        printf("Received message: %s\n", buffer);
    }

    // Close the socket
    printf("Stopping server...\n");
    close(new_socket);
    close(server_fd);

    return 0;
}
*/