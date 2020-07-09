#include <arpa/inet.h>  //close
#include <errno.h>
#include <jsoncpp/json/json.h>
#include <netinet/in.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>  //strlen
#include <sys/socket.h>
#include <sys/time.h>  //FD_SET, FD_ISSET, FD_ZERO macros
#include <sys/types.h>
#include <unistd.h>  //close

#include <fstream>
#include <iostream>

#include "Signature/signer.h"

using namespace std;

#define TRUE 1
#define FALSE 0
#define PORT 8080
#define MSG_MAX_LEN 4096
#define MAX_CLIENTS 30
#define MAX_PENDING_CONNECTIONS 3
#define CERTIFICATE_PATH "PEM/server_certificate.pem"
#define PRKEY_PATH "PEM/server_private_key.pem"
#define NONCE_SIZE 4  //La stessa di un unsigned int

// Un semplice server multi-connessione sulla porta 8080 che gestisce fino a
// 30 connessioni simultanee con buffer di lunghezza fissa

int main(int argc, char *argv[]) {
    Json::Value users;

    ifstream users_file("users.json", ifstream::binary);
    users_file >> users;

    // Strutture dati del server
    int opt = TRUE;
    int master_socket, addrlen, new_socket, client_socket[MAX_CLIENTS], activity, i, bytes_read, sd;
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
                if ((bytes_read = read(sd, buffer, MSG_MAX_LEN)) == 0) {
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

                    buffer[bytes_read] = '\0';  // ATTENZIONE: Aggiunge il carattere di fine stringa
                    string tmp;

                    // COMANDO /cert
                    if (strncmp((const char *)buffer, "/cert", bytes_read) == 0) {
                        FILE *cert_file = fopen(CERTIFICATE_PATH, "rb");
                        if (!cert_file) {
                            cerr << "Error: cannot open file '"
                                 << CERTIFICATE_PATH
                                 << "' (no permissions?)\n";
                            exit(1);
                        }

                        fseek(cert_file, 0L, SEEK_END);
                        long cert_file_size = ftell(cert_file);
                        rewind(cert_file);

                        unsigned char *certificate_buff = (unsigned char *)malloc(cert_file_size);

                        if (fread(certificate_buff, 1, cert_file_size, cert_file) < cert_file_size) {
                            cerr << "Error while reading file '"
                                 << CERTIFICATE_PATH
                                 << "'\n";
                            exit(1);
                        }
                        fclose(cert_file);

                        if (send(new_socket, certificate_buff, cert_file_size, 0) != cert_file_size) {
                            perror("Error in sending the welcome message");
                        }

                        //BIO_dump_fp(stdout, (const char *)certificate_buff, cert_file_size);

                        free(certificate_buff);

                        continue;
                    }

                    // COMANDO /list
                    if (strncmp((const char *)buffer, "/list", bytes_read) == 0) {
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
                        continue;
                    }

                    // COMANDO /challenge
                    tmp = "/challenge:";
                    if (tmp.length() < bytes_read && strncmp((const char *)buffer, tmp.c_str(), tmp.length()) == 0) {
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

                        continue;
                    }

                    // COMANDO /login
                    tmp = "/login:";
                    if (tmp.length() < bytes_read && strncmp((const char *)buffer, tmp.c_str(), tmp.length()) == 0) {
                        string username = string(buffer);
                        username = username.substr(username.find(":") + 1);
                        if (users[username].empty()) {
                            string message = "NF";
                            if (send(new_socket, message.c_str(), message.length(), 0) != message.length()) {
                                perror("Error in sending the message");
                            }
                        } else {
                            string message = "ACK";
                            if (send(new_socket, message.c_str(), message.length(), 0) != message.length()) {
                                perror("Error in sending the message");
                            }

                            // Legge (noncec)
                            if ((bytes_read = read(sd, buffer, MSG_MAX_LEN)) == 0) {
                                //Somebody disconnected , get his details and print
                                getpeername(sd, (struct sockaddr *)&address, (socklen_t *)&addrlen);
                                printf("Host disconnected , ip %s , port %d \n",
                                       inet_ntoa(address.sin_addr), ntohs(address.sin_port));

                                //Close the socket and mark as 0 in list for reuse
                                close(sd);
                                client_socket[i] = 0;
                                continue;
                            }

                            //cout << "(noncec)" << endl;
                            //BIO_dump_fp(stdout, (const char *)buffer, bytes_read);

                            // Seed OpenSSL PRNG
                            RAND_poll();

                            // Creo casualmente nonces
                            unsigned char *nonce_sc = (unsigned char *)malloc(NONCE_SIZE * 2);
                            RAND_bytes((unsigned char *)&nonce_sc[0], NONCE_SIZE);

                            // Giustappongo i nonce (nonces||noncec)
                            memcpy(nonce_sc + NONCE_SIZE, buffer, NONCE_SIZE);

                            //cout << "(nonces||noncec)" << endl;
                            //BIO_dump_fp(stdout, (const char *)nonce_sc, NONCE_SIZE*2);

                            unsigned char *signed_buff;
                            unsigned int signed_len;
                            if (sign(PRKEY_PATH, (unsigned char *)nonce_sc, NONCE_SIZE * 2, signed_buff, signed_len) != 0) {
                                perror("Not able to sign");
                                continue;
                            }

                            //cout << "sig(nonces||noncec)" << endl;
                            //BIO_dump_fp(stdout, (const char *)signed_buff, signed_len);

                            // Preparazione messaggio (nonces || sig(nonces||noncec))
                            memcpy(buffer, nonce_sc, NONCE_SIZE);
                            memcpy(buffer + NONCE_SIZE, signed_buff, signed_len);

                            //cout << "(nonces || sig(nonces||noncec))" << endl;
                            //BIO_dump_fp(stdout, (const char *)buffer, signed_len + NONCE_SIZE);

                            if (send(new_socket, buffer, signed_len + NONCE_SIZE, 0) != signed_len + NONCE_SIZE) {
                                perror("Error in sending the message");
                            }

                            free(signed_buff);

                            // sig(nonces)
                            if ((bytes_read = read(sd, buffer, MSG_MAX_LEN)) == 0) {
                                //Somebody disconnected , get his details and print
                                getpeername(sd, (struct sockaddr *)&address, (socklen_t *)&addrlen);
                                printf("Host disconnected , ip %s , port %d \n",
                                       inet_ntoa(address.sin_addr), ntohs(address.sin_port));

                                //Close the socket and mark as 0 in list for reuse
                                close(sd);
                                client_socket[i] = 0;
                                continue;
                            }

                            // Verify sig(nonces)
                            if (verify_sign(users[username]["pub_key"].asString(), nonce_sc, NONCE_SIZE, (unsigned char *)buffer, bytes_read) == 0) {
                                string message = "ACK";
                            } else {
                                string message = "NV";
                            }

                            if (send(new_socket, message.c_str(), message.length(), 0) != message.length()) {
                                perror("Error in sending the message");
                            }

                            // Prende le informazioni sull'utente e le salva nella struttura json (non nel file)
                            getpeername(sd, (struct sockaddr *)&address, (socklen_t *)&addrlen);
                            users[username]["IP"] = inet_ntoa(address.sin_addr);
                            users[username]["PORT"] = ntohs(address.sin_port);
                            users[username]["online"] = true;

                            unsigned int* nonce_s_pointer = (unsigned int *)malloc(NONCE_SIZE + 1);
                            memcpy(nonce_s_pointer, nonce_sc, NONCE_SIZE);

                            unsigned int nonce_s = *nonce_s_pointer;

                            users[username]["nonce"] = nonce_s;

                            cout << users << endl;

                        }
                        unsigned char *nonce_sc = (unsigned char *)malloc(NONCE_SIZE * 2);
                        continue;
                    }

                    // Comando non valido
                    string message = "Command not valid";
                    if (send(new_socket, message.c_str(), message.length(), 0) != message.length()) {
                        perror("Error in sending the message");
                    }

                    //FINE SECONDA CONNESSIONE IN POI-----------------------------------------------------------------------------------------------
                }
            }
        }
    }

    return 0;
}