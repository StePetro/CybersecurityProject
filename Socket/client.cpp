// Client connection
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

#define PORT 8080

class ClientConnection{

        int sock = 0, valread;
        struct sockaddr_in address;
        char buffer[1024] = {0}; // VA ASSOLUTAMENTE CAMBIATO Con un buffer di dimensione opportuna!!!!!!!!!!!

    public:

        int initialization(char const *IP_Server){
            // Formatta l'indirizzo del destinatario, sulla porta 8080

            if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0){
                printf("\n Socket creation error \n");
                return -1;
            }

            address.sin_family = AF_INET;
            address.sin_port = htons(PORT);

            // Convert IPv4 and IPv6 addresses from text to binary form
            if (inet_pton(AF_INET, IP_Server, &address.sin_addr) <= 0){
                printf("\nInvalid address/ Address not supported \n");
                return -1;
            }

            if (connect(sock, (struct sockaddr *)&address, sizeof(address)) < 0){
                printf("\nConnection Failed \n");
                return -1;
            }

            return 0;
        };

        int send_msg(char const *msg){
            // Invia il messaggio
            send(sock, msg, strlen(msg), 0);
            return 0;
        };

        int read_reply(){
            // Stampa a schermo la risposta
            valread = read(sock, buffer, 1024);
            printf("%s\n", buffer);
            return 0;
        };
};

main(int argc, char const *argv[]){
    
    ClientConnection cc;
    cc.initialization("172.16.1.242");
    cc.send_msg("Prova1");
    cc.send_msg("Prova2");
    cc.read_reply();

    return 0;
}