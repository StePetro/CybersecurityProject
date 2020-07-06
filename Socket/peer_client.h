// Client connection
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define MSG_MAX_LEN 1024

class PeerClientConnection {
    int sock = 0, valread;
    struct sockaddr_in address;

   public:
    int initialization(char const *IP_Server, u_int16_t PORT_Server) {
        // Avvia la connessione con il server alla porta 8888 (del server),
        // casuale per il client

        if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            printf("\nSocket creation error \n");
            return -1;
        }

        address.sin_family = AF_INET;
        address.sin_port = htons(PORT_Server);

        // Convert IPv4 and IPv6 addresses from text to binary form
        if (inet_pton(AF_INET, IP_Server, &address.sin_addr) <= 0) {
            printf("\nInvalid address/ Address not supported \n");
            return -1;
        }

        if (connect(sock, (struct sockaddr *)&address, sizeof(address)) < 0) {
            printf("\nConnection Failed \n");
            return -1;
        }

        return 0;
    };

    int send_msg(char const *msg) {
        // Invia il messaggio
        if (send(sock, msg, strlen(msg), 0) < strlen(msg)) {
            printf("\nSent fewer bytes than expected \n");
            return -1;
        }
        return 0;
    };

    int read_msg(unsigned char *buffer) {
        // Copia il messaggio nel buffer, aggiunge il carattere
        // di fine stringa e ritorna il numero di
        // byte letti (carattere di fine stringa escluso)
        int bytes_read = read(sock, buffer, MSG_MAX_LEN);
        if (bytes_read < 0) {
            printf("\nError in message reading \n");
            return -1;
        }
        // Manca il carattere di fine stringa
        buffer[bytes_read] = '\0';
        return bytes_read;
    };
};