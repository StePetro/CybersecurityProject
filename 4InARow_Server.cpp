#include "Handler/handler_server.h"
// Un semplice server multi-connessione sulla porta 8080 che gestisce fino a
// 30 connessioni simultanee con buffer di lunghezza fissa

int main(int argc, char *argv[]) {
    Json::Value users;
    Json::Value logged_users;

    ifstream users_file("users.json", ifstream::binary);
    users_file >> users;

    // Strutture dati del server
    int opt = TRUE;
    int master_socket, addrlen, new_socket, socket_list[MAX_CLIENTS], activity, i, bytes_read, socket_id;
    int max_sd;
    struct sockaddr_in address;
    // Puntatori a puntatori di buffer conteneti nonce e chiavi di sessioni
    unsigned char *nonce_list[MAX_CLIENTS];
    unsigned char *session_key_list[MAX_CLIENTS];

    for (int i = 0; i < MAX_CLIENTS; i++) {
        nonce_list[i] = new unsigned char[NONCE_SIZE];
#pragma optimize("", off)
        memset(nonce_list[i], 0, NONCE_SIZE);
#pragma optimize("", on)
        
    }

    char buffer[MSG_MAX_LEN];  //data buffer of 1K

    //set of socket descriptors
    fd_set readfds;

    //initialise all socket_list[] to 0 so not checked
    for (i = 0; i < MAX_CLIENTS; i++) {
        socket_list[i] = 0;
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
    cout << "Listener on port "<< PORT << endl;

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
            socket_id = socket_list[i];

            //if valid socket descriptor then add to read list
            if (socket_id > 0)
                FD_SET(socket_id, &readfds);

            //highest file descriptor number, need it for the select function
            if (socket_id > max_sd)
                max_sd = socket_id;
        }

        //wait for an activity on one of the sockets , timeout is NULL ,
        //so wait indefinitely
        activity = select(max_sd + 1, &readfds, NULL, NULL, NULL);

        if ((activity < 0) && (errno != EINTR)) {
            cerr << "select error" << endl;
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
                if (socket_list[i] == 0) {
                    socket_list[i] = new_socket;
                    printf("Adding to list of sockets as %d\n", i);
                    break;
                }
            }
        }

        //else its some IO operation on some other socket
        for (i = 0; i < MAX_CLIENTS; i++) {
            socket_id = socket_list[i];

            if (FD_ISSET(socket_id, &readfds)) {
                //Check if it was for closing , and also read the
                //incoming message

                //SECONDA CONNESSIONE IN POI-----------------------------------------------------------------------------------------------

                if ((bytes_read = read(socket_id, buffer, MSG_MAX_LEN)) == 0) {
                    //Somebody disconnected , get his details and print
                    getpeername(socket_id, (struct sockaddr *)&address, (socklen_t *)&addrlen);
                    printf("Host disconnected , ip %s , port %d \n",
                           inet_ntoa(address.sin_addr), ntohs(address.sin_port));

                    //Close the socket and mark as 0 in list for reuse
                    close(socket_id);
                    socket_list[i] = 0;
                    if (!logged_users[i].empty()) {
                        //Toglie l'utente disconnesso dalla lista
                        users[logged_users[i].asString()]["IP"] = {};
                        users[logged_users[i].asString()]["PORT"] = {};
                        users[logged_users[i].asString()]["READY"] = {};
                        users[logged_users[i].asString()]["i"] = {};
                        logged_users[i] = {};
                        #pragma optimize("", off)
                        memset(nonce_list[i], 0, NONCE_SIZE);
                        memset(session_key_list[i], 0, SESSION_KEY_SIZE);
                        #pragma optimize("", on)
                    }
                } else {                        // Risposta del server
                    buffer[bytes_read] = '\0';  // ATTENZIONE: Aggiunge il carattere di fine stringa
                    string tmp;
                    unsigned char *decrypted_msg = NULL;
                    unsigned int decrypted_msg_len = 0;

                    // Incremento il nonce di 1 se user loggato
                    if (!logged_users[i].empty()) {
                        nonce_add_one(nonce_list[i]);
                        if (memcmp(buffer + IV_LEN, nonce_list[i], NONCE_SIZE) != 0) {
                            cerr << "Wrong nonce" << endl;
                            close_socket_logged(socket_list[i], socket_list, users, logged_users, session_key_list, nonce_list, i);
                            continue;
                        }
                        if (gcm_decrypt((unsigned char *)buffer, bytes_read, NONCE_SIZE, session_key_list[i], decrypted_msg, decrypted_msg_len) != 0) {
                            cerr << "Decryption failed" << endl;
                            close_socket_logged(socket_list[i], socket_list, users, logged_users, session_key_list, nonce_list, i);
                            continue;
                        }
                    }

                    // COMANDO /cert
                    if (strncmp((const char *)buffer, "/cert", bytes_read) == 0) {
                        if (cert_handler(socket_id) == 0) {
                            continue;
                        }
                    }

                    // COMANDO /login
                    tmp = "/login:";
                    if (tmp.length() < bytes_read && strncmp((const char *)buffer, tmp.c_str(), tmp.length()) == 0) {
                        if (login_handler(socket_id, users, logged_users, buffer, address, addrlen, socket_list, i, session_key_list) == 0) {
                            // Parte da 0 con il nonce e lo incrementa da ora in poi

                            #pragma optimize("", off)
                            memset(nonce_list[i], 0, NONCE_SIZE);
                            #pragma optimize("", on)
                            continue;
                        }
                        // Se il login fallisce
                        // Disconnessione, print delle informazioni
                        getpeername(socket_id, (struct sockaddr *)&address, (socklen_t *)&addrlen);
                        printf("Host disconnected , ip %s , port %d \n",
                               inet_ntoa(address.sin_addr), ntohs(address.sin_port));

                        // Chiusura socket, marcato con 0 per essere riutilizzato
                        close(socket_id);
                        socket_list[i] = 0;
                        logged_users[i] = {};
                    }

                    // Comandi per utenti loggati
                    if (!logged_users[i].empty()) {
                        string message = "ERR";
                        unsigned char *final_msg;
                        unsigned int final_msg_len;

                        // COMANDO /list
                        if (decrypted_msg != NULL && strncmp((const char *)decrypted_msg, "/list", decrypted_msg_len) == 0) {
                            // Elenca solo gli utenti online e loggati
                            message = "Users ready:";
                            for (int i = 0; i < MAX_CLIENTS; i++) {
                                // RIMETTERE A TRUE
                                if (!logged_users[i].empty() && users[logged_users[i].asString()]["READY"].asBool()) {
                                    message += "\n- ";
                                    message += logged_users[i].asString();
                                }
                            }
                            message += "\nIf you want to challenge someone type: \"/challenge:[user]\"";
                        }

                        // COMANDO /find
                        if (strncmp((const char *)decrypted_msg, "/find", decrypted_msg_len) == 0) {
                            users[logged_users[i].asString()]["READY"] = true;
                            users[logged_users[i].asString()]["i"] = i;
                            continue;
                        }

                        // COMANDO /challenge
                        tmp = "/challenge:";
                        if (tmp.length() < decrypted_msg_len && strncmp((const char *)decrypted_msg, tmp.c_str(), tmp.length()) == 0) {
                           if(challenge_handler(buffer, i, socket_id, socket_list, decrypted_msg, decrypted_msg_len, message, users, logged_users, nonce_list, session_key_list) >= 0){
                               continue;
                           }
                        }

                        send_encrypted((unsigned char *)message.c_str(), message.length(), nonce_list[i], NONCE_SIZE, session_key_list[i], nonce_list[i], socket_id);
                        continue;
                    }

                    // Comando non valido o errore nei comandi precedenti
                    string message = "ERR";
                    if (send(socket_id, message.c_str(), message.length(), 0) != message.length()) {
                        perror("Error in sending the message");
                    }

                    delete[] decrypted_msg;
                    decrypted_msg_len = 0;

                    //FINE SECONDA CONNESSIONE IN POI-----------------------------------------------------------------------------------------------
                }
            }
        }
    }

    return 0;
}