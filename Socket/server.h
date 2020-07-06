// Server connection

#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>

// Il server o il peer in vece di server espongono sempre
// la porta 8080 per permettere la connessione
#define PORT 8080
#define MSG_MAX_LEN 1024

class ServerConnection{

        int server_fd, new_socket, valread;
        struct sockaddr_in address;
        int opt = 1;
        int addrlen = sizeof(address);

    public:

        int initialization(){
            // Formatta l'indirizzo del destinatario, sulla porta 8080

            // Creating socket file descriptor
            if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0){
                perror("Error in creating the socket");
                exit(EXIT_FAILURE);
            }

            // Forcefully attaching socket to the port 8080
            if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
                        &opt, sizeof(opt))){
                perror("Error in setting socket options");
                exit(EXIT_FAILURE);
            }
            address.sin_family = AF_INET;
            address.sin_addr.s_addr = INADDR_ANY;
            address.sin_port = htons(PORT);

            // Forcefully attaching socket to the port 8080
            if (bind(server_fd, (struct sockaddr *)&address,
                    sizeof(address)) < 0){
                perror("Bind failed");
                exit(EXIT_FAILURE);
            }

            if (listen(server_fd, 3) < 0){
                perror("Error on the listen");
                exit(EXIT_FAILURE);
            }

            if ((new_socket = accept(server_fd, (struct sockaddr *)&address,
                                    (socklen_t *)&addrlen)) < 0){
                perror("Error on the accept");
                exit(EXIT_FAILURE);
            }

            return 0;
        };

        int send_reply(char const *msg){
            // Invia la risposta
            if(send(new_socket, msg, strlen(msg), 0) < strlen(msg)){
                perror("Sent fewer bytes than expected");
                exit(EXIT_FAILURE);
            }
            return 0;
        };

        int read_msg(unsigned char* buffer){
            // Copia il messaggio nel buffer, aggiunge il carattere
            // di fine stringa e ritorna il numero di
            // byte letti (carattere di fine stringa escluso)
            int bytes_read = read(new_socket, buffer, MSG_MAX_LEN);
            if(bytes_read < 0){
                perror("Error in message reading");
                exit(EXIT_FAILURE);
            }
            // Manca il carattere di fine stringa
            buffer[bytes_read] = '\0';
            return bytes_read;
        };
};