#include <arpa/inet.h>  //close
#include <errno.h>
#include <jsoncpp/json/json.h>
#include <netinet/in.h>
#include <openssl/bio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>  //strlen
#include <sys/socket.h>
#include <sys/time.h>  //FD_SET, FD_ISSET, FD_ZERO macros
#include <sys/types.h>
#include <unistd.h>  //close

#include <fstream>
#include <iostream>

using namespace std;

#define TRUE 1
#define FALSE 0
#define PORT 8080
#define MSG_MAX_LEN 4096
#define MAX_CLIENTS 30
#define MAX_PENDING_CONNECTIONS 3

// Un semplice server multi-connessione sulla porta 8080 che gestisce fino a
// 30 connessioni simultanee con messaggi di lunghezza fissa

int main(int argc, char *argv[]) {
    Json::Value users;

    ifstream users_file("users.json", ifstream::binary);
    users_file >> users;

    // Strutture dati del server
    int opt = TRUE;
    int master_socket, addrlen, new_socket, client_socket[MAX_CLIENTS], activity, i, valread, sd;
    int max_sd;
    struct sockaddr_in address;

    char buffer[MSG_MAX_LEN];  //data buffer of 1K

    //set of socket descriptors
    fd_set readfds;

    //initialise all client_socket[] to 0 so not checked
    for (i = 0; i < MAX_CLIENTS; i++) {
        client_socket[i] = 0;
    }

    //create a master socket
    if ((master_socket = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    //set master socket to allow multiple connections ,
    //this is just a good habit, it will work without this
    if (setsockopt(master_socket, SOL_SOCKET, SO_REUSEADDR, (char *)&opt,
                   sizeof(opt)) < 0) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    //type of socket created
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    //bind the socket to localhost port PORT
    if (bind(master_socket, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    printf("Listener on port %d \n", PORT);

    //try to specify maximum of MAX_PENDING_CONNECTIONS pending connections for the master socket
    if (listen(master_socket, MAX_PENDING_CONNECTIONS) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    //accept the incoming connection
    addrlen = sizeof(address);
    puts("Waiting for connections ...");

    while (TRUE) {
        //clear the socket set
        FD_ZERO(&readfds);

        //add master socket to set
        FD_SET(master_socket, &readfds);
        max_sd = master_socket;

        //add child sockets to set
        for (i = 0; i < MAX_CLIENTS; i++) {
            //socket descriptor
            sd = client_socket[i];

            //if valid socket descriptor then add to read list
            if (sd > 0)
                FD_SET(sd, &readfds);

            //highest file descriptor number, need it for the select function
            if (sd > max_sd)
                max_sd = sd;
        }

        //wait for an activity on one of the sockets , timeout is NULL ,
        //so wait indefinitely
        activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);

        if ((activity < 0) && (errno != EINTR)) {
            printf("select error");
        }

        //If something happened on the master socket ,
        //then its an incoming connection
        if (FD_ISSET(master_socket, &readfds)) {
            if ((new_socket = accept(master_socket,
                                     (struct sockaddr *)&address, (socklen_t *)&addrlen)) < 0) {
                perror("accept");
                exit(EXIT_FAILURE);
            }

            //PRIMA CONNESSIONE -----------------------------------------------------------------------------------------------

            // Informazioni sulla connessione
            printf("New connection , socket fd is %d , ip is : %s , port : %d \n", new_socket, inet_ntoa(address.sin_addr), ntohs(address.sin_port));

            // Messaggio di benvenuto
            const char *message = "Welcome to Four in a Row!\nTo receive the certificate type: \"/cert\"";
            if (send(new_socket, message, strlen(message), 0) != strlen(message)) {
                perror("Error in sending the welcome message");
            }

            //FINE PRIMA CONNESSIONE -----------------------------------------------------------------------------------------------

            //add new socket to array of sockets
            for (i = 0; i < MAX_CLIENTS; i++) {
                //if position is empty
                if (client_socket[i] == 0) {
                    client_socket[i] = new_socket;
                    printf("Adding to list of sockets as %d\n", i);
                    break;
                }
            }
        }

        //else its some IO operation on some other socket
        for (i = 0; i < MAX_CLIENTS; i++) {
            sd = client_socket[i];

            if (FD_ISSET(sd, &readfds)) {
                //Check if it was for closing , and also read the
                //incoming message
                if ((valread = read(sd, buffer, MSG_MAX_LEN)) == 0) {
                    //Somebody disconnected , get his details and print
                    getpeername(sd, (struct sockaddr *)&address, (socklen_t *)&addrlen);
                    printf("Host disconnected , ip %s , port %d \n",
                           inet_ntoa(address.sin_addr), ntohs(address.sin_port));

                    //Close the socket and mark as 0 in list for reuse
                    close(sd);
                    client_socket[i] = 0;
                }

                //Response from the server
                else {
                    //SECONDA CONNESSIONE IN POI-----------------------------------------------------------------------------------------------

                    bool managed = false;
                    buffer[valread] = '\0';  // ATTENZIONE: Aggiunge il carattere di fine stringa

                    // COMANDO /cert
                    if (strncmp((const char *)buffer, "/cert", valread) == 0) {
                        FILE *cert_file = fopen("PEM/server_certificate.pem", "rb");
                        if (!cert_file) {
                            cerr << "Error: cannot open file '"
                                 << "PEM/server_certificate.pem"
                                 << "' (no permissions?)\n";
                            exit(1);
                        }

                        fseek(cert_file, 0L, SEEK_END);
                        long cert_file_size = ftell(cert_file);
                        rewind(cert_file);

                        unsigned char *certificate_buff = (unsigned char *)malloc(cert_file_size + sizeof(long));

                        memcpy(certificate_buff, &cert_file_size, sizeof(long));

                        BIO_dump_fp(stdout, (const char *)certificate_buff, cert_file_size + sizeof(long));

                        if (fread(certificate_buff + sizeof(long), 1, cert_file_size, cert_file) < cert_file_size) {
                            cerr << "Error while reading file '"
                                 << "PEM/server_certificate.pem"
                                 << "'\n";
                            exit(1);
                        }
                        fclose(cert_file);

                        if (send(new_socket, certificate_buff, cert_file_size + sizeof(long), 0) != cert_file_size + sizeof(long)) {
                            perror("Error in sending the welcome message");
                        }

                        BIO_dump_fp(stdout, (const char *)certificate_buff, cert_file_size + sizeof(long));

                        free(certificate_buff);
                        managed = true;
                    }

                    // COMANDO /list
                    if (strncmp((const char *)buffer, "/list", valread) == 0) {
                        string message = "Users:\n";
                        for (auto const &user : users.getMemberNames()) {
                            message += "- ";
                            message += user;
                            message += "\n";
                        }
                        message += "\nIf you want to challenge someone type: \"/challenge:[user]\"";
                        if (send(new_socket, message.c_str(), message.length(), 0) != message.length()) {
                            perror("Error in sending the message");
                        }
                        managed = true;
                    }

                    // COMANDO /challenge
                    if (12 < valread && strncmp((const char *)buffer, "/challenge:", 11) == 0) {
                        string username = string(buffer);
                        username = username.substr(username.find(":") + 1);
                        string ip = users[username]["ip"].asString();
                        if (ip.compare("") == 0) {
                            string message = "User not found";
                            if (send(new_socket, message.c_str(), message.length(), 0) != message.length()) {
                                perror("Error in sending the message");
                            }
                        } else {
                            string message = username + " IP is: " + ip;
                            if (send(new_socket, message.c_str(), message.length(), 0) != message.length()) {
                                perror("Error in sending the message");
                            }
                        }

                        managed = true;
                    }

                    // Comando non valido
                    if (managed == false) {
                        string message = "Command not valid";
                        if (send(new_socket, message.c_str(), message.length(), 0) != message.length()) {
                            perror("Error in sending the message");
                        }
                    }

                    //FINE SECONDA CONNESSIONE IN POI-----------------------------------------------------------------------------------------------
                }
            }
        }
    }

    return 0;
}