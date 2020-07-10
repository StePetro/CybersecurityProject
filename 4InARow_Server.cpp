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

#include "Key_Exchange/DHKE.h"
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
#define NONCE_SIZE 128  //La stessa di un unsigned int

// Unsigned int a 128 bit, presente solo su alcuni compilatori
typedef unsigned __int128 uint128_t;

int cert_handler(int socket) {
    // Apre il file del certificato
    FILE *cert_file = fopen(CERTIFICATE_PATH, "rb");
    if (!cert_file) {
        cerr << "Error: cannot open file '"
             << CERTIFICATE_PATH
             << "' (no permissions?)\n";
        return -1;
    }

    // Legge la lunghezza del certificato
    fseek(cert_file, 0L, SEEK_END);
    long cert_file_size = ftell(cert_file);
    rewind(cert_file);

    // Alloca una buffer per salvare il certificato in memoria
    unsigned char *certificate_buff = new unsigned char[cert_file_size];

    // Scrive il certificato nel buffer
    if (fread(certificate_buff, 1, cert_file_size, cert_file) < cert_file_size) {
        cerr << "Error while reading file '"
             << CERTIFICATE_PATH
             << "'\n";
        return -1;
    }
    fclose(cert_file);

    // Spedisce il certificato in risposta all'utente
    if (send(socket, certificate_buff, cert_file_size, 0) != cert_file_size) {
        perror("Error in sending the welcome message");
        return -1;
    }

    // Dealloca la memoria del buffer
    delete[] certificate_buff;
    return 0;
}

int login_handler(int socket, Json::Value &users, Json::Value &socket_slots, char *buffer, sockaddr_in address, int addrlen, int *client_socket, int i) {
    int bytes_read;
    string username = string(buffer);
    // Nome utente
    username = username.substr(username.find(":") + 1);
    if (users[username].empty()) {
        // Se non è nel json risponde Not Found
        string message = "NF";
        if (send(socket, message.c_str(), message.length(), 0) != message.length()) {
            cerr << "Error in sending the message" << endl;
        }
        return -1;
    }

    if (!users[username]["nonce"].empty()) {
        // L'utente è già online
        string message = "AL";
        if (send(socket, message.c_str(), message.length(), 0) != message.length()) {
            cerr << "Error in sending the message" << endl;
        }
        return -1;
    }

    // Altrimenti manda un ACK se presente
    string message = "ACK";
    if (send(socket, message.c_str(), message.length(), 0) != message.length()) {
        cerr << "Error in sending the message" << endl;
        return -1;
    }

    // Legge (nonce_c) dal client
    if ((bytes_read = read(socket, buffer, MSG_MAX_LEN)) == 0) {
        // Disconnessione, print delle informazioni
        getpeername(socket, (struct sockaddr *)&address, (socklen_t *)&addrlen);
        printf("Host disconnected , ip %s , port %d \n",
               inet_ntoa(address.sin_addr), ntohs(address.sin_port));

        // Chiusura socket, marcato con 0 per essere riutilizzato
        close(socket);
        client_socket[i] = 0;
        socket_slots[i] = {};
        return -1;
    }

    // Creo casualmente nonce_s del server
    RAND_poll();
    unsigned char *nonce_s = new unsigned char[NONCE_SIZE];  // Alloco per due nonce in modo da giustapporli
    RAND_bytes((unsigned char *)&nonce_s[0], NONCE_SIZE);

    // Firma digitale di nonce_c (nel buffer) con la chiave privata del server
    unsigned char *signed_buff;
    unsigned int signed_len;
    if (sign(PRKEY_PATH, (unsigned char *)buffer, NONCE_SIZE, signed_buff, signed_len) != 0) {
        cerr << "Not able to sign" << endl;
        return -1;
    }

    // Preparazione messaggio (nonces || sgn(nonce_c))
    memcpy(buffer, nonce_s, NONCE_SIZE);
    memcpy(buffer + NONCE_SIZE, signed_buff, signed_len);

    // Invio (nonces || (nonces || sgn(nonce_c)))
    if (send(socket, buffer, signed_len + NONCE_SIZE, 0) != signed_len + NONCE_SIZE) {
        cerr << "Error in sending the message" << endl;
        return -1;
    }

    delete[] signed_buff;

    // Il client risponde con la firma del nonce del server: sig(nonce_s)
    if ((bytes_read = read(socket, buffer, MSG_MAX_LEN)) == 0) {
        // Disconnessione, print delle informazioni
        getpeername(socket, (struct sockaddr *)&address, (socklen_t *)&addrlen);
        printf("Host disconnected , ip %s , port %d \n",
               inet_ntoa(address.sin_addr), ntohs(address.sin_port));

        // Chiusura socket, marcato con 0 per essere riutilizzato
        close(socket);
        client_socket[i] = 0;
        socket_slots[i] = {};
        return -1;
    }

    // Verifica se la firma sig(nonce_s) è valida, tramite la chiave pubblica dell'utente che si sta loggando
    if (verify_sign(users[username]["pub_key"].asString(), nonce_s, NONCE_SIZE, (unsigned char *)buffer, bytes_read) == 0) {
        string message = "ACK";  // Se era giusta
        if (send(socket, message.c_str(), message.length(), 0) != message.length()) {
            cerr << "Error in sending the message" << endl;
            return -1;
        }
    } else {
        string message = "NV";  // Se non era valida
        if (send(socket, message.c_str(), message.length(), 0) != message.length()) {
            cerr << "Error in sending the message" << endl;
        }
        return -1;
    }

    // Prende le informazioni sull'utente e le salva nella struttura json in memoria (non nel file)
    getpeername(socket, (struct sockaddr *)&address, (socklen_t *)&addrlen);
    users[username]["IP"] = inet_ntoa(address.sin_addr);
    users[username]["PORT"] = ntohs(address.sin_port);

    // Parte da 0 con il nonce e lo incrementa da ora in poi
    uint128_t nonce = 0;
    users[username]["nonce_pointer"] = &nonce;
    cout << users << endl;
    delete[] nonce_s;

    // Aggiungo anche l'informazione su quale user sta usando un certo slot dei socket
    socket_slots[i] = username;

    //INIZIO NEGOZIAZIONE CHIAVE DI SESSIONE -------------------------------------------------------------------------
    /*
    EVP_PKEY *params = NULL;
    EVP_PKEY *keys_server = NULL;  // Sia privata che pubblica
    EVP_PKEY *public_key_server = NULL;
    EVP_PKEY *public_key_client = NULL;
    unsigned char *session_key = NULL;

    // Creazione dei parametri "g" ed "n"
    if (create_DH_params(params) != 0) {
        cerr << "Error in parameters' creation" << endl;
        return -1;
    }

    // Creazioni chiavi effimere
    if(create_ephemeral_keys(params, keys_server, public_key_server) != 0){
        cerr << "Error in ephemeral keys' creation" << endl;
        return -1;
    }

    // messaggio = (nonce + 1 || params || public_key_server || sgn(nonce + 1 || params || public_key_server) )
    users[username]["nonce"] = users[username]["nonce"].asUInt() + 1;
    
    unsigned char* to_sign_buff = new unsigned char[NONCE_SIZE + EVP_PKEY_size(params) + EVP_PKEY_size(public_key_server)];
    to_sign_buff[0] = users[username]["nonce"].asUInt();
    */
    return 0;
}

// Un semplice server multi-connessione sulla porta 8080 che gestisce fino a
// 30 connessioni simultanee con buffer di lunghezza fissa

int main(int argc, char *argv[]) {
    Json::Value users;
    Json::Value socket_slots;

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

                //SECONDA CONNESSIONE IN POI-----------------------------------------------------------------------------------------------

                if ((bytes_read = read(sd, buffer, MSG_MAX_LEN)) == 0) {
                    //Somebody disconnected , get his details and print
                    getpeername(sd, (struct sockaddr *)&address, (socklen_t *)&addrlen);
                    printf("Host disconnected , ip %s , port %d \n",
                           inet_ntoa(address.sin_addr), ntohs(address.sin_port));

                    //Close the socket and mark as 0 in list for reuse
                    close(sd);
                    client_socket[i] = 0;
                    if (!socket_slots[i].empty()) {
                        //Toglie l'utente disconnesso dalla lista
                        users[socket_slots[i].asString()]["IP"] = {};
                        users[socket_slots[i].asString()]["PORT"] = {};
                        users[socket_slots[i].asString()]["nonce"] = {};
                        socket_slots[i] = {};
                    }
                } else {                        // Risposta del server
                    buffer[bytes_read] = '\0';  // ATTENZIONE: Aggiunge il carattere di fine stringa
                    string tmp;

                    // COMANDO /cert
                    if (strncmp((const char *)buffer, "/cert", bytes_read) == 0) {
                        if (cert_handler(sd) == 0) {
                            continue;
                        }
                    }

                    // COMANDO /login
                    tmp = "/login:";
                    if (tmp.length() < bytes_read && strncmp((const char *)buffer, tmp.c_str(), tmp.length()) == 0) {
                        if (login_handler(sd, users, socket_slots, buffer, address, addrlen, client_socket, i) == 0) {
                            continue;
                        }
                    }

                    // Comandi disponibili solo agli utenti loggati
                    if (!socket_slots[i].empty()) {
                        // COMANDO /list
                        if (strncmp((const char *)buffer, "/list", bytes_read) == 0) {
                            // Elenca solo gli utenti online e loggati
                            string message = "Online users:";
                            for (i = 0; i < MAX_CLIENTS; i++) {
                                if (!socket_slots[i].empty())
                                    message += "\n- ";
                                message += socket_slots[i].asString();
                            }
                            message += "\nIf you want to challenge someone type: \"/challenge:[user]\"";
                            if (send(sd, message.c_str(), message.length(), 0) != message.length()) {
                                perror("Error in sending the message");
                            }
                            continue;
                        }

                        /*

                        // COMANDO /challenge
                        tmp = "/challenge:";
                        if (tmp.length() < bytes_read && strncmp((const char *)buffer, tmp.c_str(), tmp.length()) == 0) {
                            string username = string(buffer);
                            username = username.substr(username.find(":") + 1);
                            string ip = users[username]["ip"].asString();
                            if (ip.compare("") == 0) {
                                string message = "User not found";
                                if (send(sd, message.c_str(), message.length(), 0) != message.length()) {
                                    perror("Error in sending the message");
                                    continue;
                                }
                            } else {
                                string message = username + " IP is: " + ip;
                                if (send(sd, message.c_str(), message.length(), 0) != message.length()) {
                                    perror("Error in sending the message");
                                    continue;
                                }
                            }

                            continue;
                        }*/
                    }

                    // Comando non valido o errore nei comandi precedenti
                    string message = "ERR";
                    if (send(sd, message.c_str(), message.length(), 0) != message.length()) {
                        perror("Error in sending the message");
                    }

                    //FINE SECONDA CONNESSIONE IN POI-----------------------------------------------------------------------------------------------
                }
            }
        }
    }

    return 0;
}