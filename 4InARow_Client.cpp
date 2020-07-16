#include "Handler/handler_client.h"

main(int argc, char const *argv[]) {
    // Strutture dati utili
    char msg_buffer[MSG_MAX_LEN] = {0};
    long bytes_read = 0;
    unsigned char *session_key_server = NULL;
    unsigned char nonce_server[NONCE_SIZE] = {0};
    string pkey_path;

    // Socket client
    PeerClientConnection cc;
    cc.initialization(IP_SERVER, SERVER_PORT);

    // Lettura messaggio benvenuto
    if ((bytes_read = cc.read_msg((unsigned char *)msg_buffer)) == 0) {
        cout << "Server disconnected" << endl;
        exit(1);
    }
    printf("%s\n", msg_buffer);

    while (true) {
        // richiesta inserimento comando del client
        string msg;
        cout << "\nPlease type a command: ";
        cin >> msg;
        if (msg.compare("/exit") == 0 || msg.compare("/quit") == 0) {
            // Chiudo la connessione ed esco
            cout << "Thanks for playing, goodbye!" << endl;
            break;
        }

        // subito dopo l'inserimento del comando mando msg al server
        //(chiaramente il modo in cui devo mandare il messaggio cambia se sono loggato o meno)
        if (session_key_server != NULL) {
            // mando il comando cryptato
            unsigned char *final_msg;
            unsigned int final_msg_len;
            // il nonce va incrementato prima di inviare/ricevere un messaggio
            nonce_add_one(nonce_server);
            gcm_encrypt((unsigned char *)msg.c_str(), msg.length(), nonce_server, NONCE_SIZE, session_key_server, final_msg, final_msg_len);
            cc.send_msg(final_msg, final_msg_len);
        } else {
            // Comandi da NON loggato
            cc.send_msg(msg);
        }

        // A seconda del comando inserito lo gestisco in maniera appropriata
        // Gestione richiesta login (solo se l'utente è loggato)
        if (msg.compare(0, string("/login:").size(), "/login:") == 0 && session_key_server == NULL) {
            if (login_handler(pkey_path, (unsigned char *)msg_buffer, cc, session_key_server, msg.substr(msg.find(":") + 1)) != 0) {
                cerr << "Login failed" << endl;
                break;
            }
            continue;
        }

        // Gestione richiesta certificato
        if (msg.compare("/cert") == 0 && session_key_server == NULL) {
            if (cert_handler((unsigned char *)msg_buffer, cc) != 0) {
                cerr << "Certificate NOT verified" << endl;
            }
            continue;
        }

        // Gestione richiesta di cercare uno sfidante (solo se l'utente è loggato)
        if (msg.compare("/find") == 0 && session_key_server != NULL) {
            cout << "I'm looking for a challenger..." << endl;
            if (find_handler(pkey_path, (unsigned char *)msg_buffer, cc, session_key_server, nonce_server) != 0) {
                // notifico errore, oppure rifiuto da parte dello sfidato
                continue;
            }
        }

        // Gestione richiesta di cercare uno sfidante (solo se l'utente è loggato)
        if (msg.compare(0, string("/challenge:").size(), "/challenge:") == 0 && session_key_server != NULL) {
            cout << "Waiting response..." << endl;
            challenge_handler(pkey_path, (unsigned char *)msg_buffer, cc, session_key_server, nonce_server);
            continue;
        }

        // Se arrivo qua significa che il comando mandato al server non era tra quelli riconosciuti
        // Devo comunque ascoltare la risposta sennò il server parla a vuoto
        // Lettura risposta server di default
        if ((bytes_read = cc.read_msg((unsigned char *)msg_buffer)) == 0) {
            cerr << "Server disconnected" << endl;
            exit(-1);
        }

        // Incremento il nonce di 1
        if (session_key_server != NULL) {
            unsigned char *decrypted_msg;
            unsigned int decrypted_msg_len;

            // il nonce va incrementato ad ogni invio e ricezione di un nuovo messaggio, poi lo controlliamo
            nonce_add_one(nonce_server);
            if (memcmp(msg_buffer + IV_LEN, nonce_server, NONCE_SIZE) != 0) {
                cerr << "Wrong nonce, aborting connection" << endl;
                break;
            }

            if (gcm_decrypt((unsigned char *)msg_buffer, bytes_read, NONCE_SIZE, session_key_server, decrypted_msg, decrypted_msg_len) != 0) {
                cerr << "A problem has occurred while decrypting the message. \n Aborting connection..." << endl;
                break;
            }
            string err = "ERR";
            if (err.compare(0, decrypted_msg_len, (const char *)decrypted_msg) == 0) {
                cout << "Error: possible wrong command" << endl;
            } else {
                cout << decrypted_msg << endl;
            }
        } else {
            string err = "ERR";
            if (err.compare(0, bytes_read, (const char *)msg_buffer) == 0) {
                cout << "Error: possible wrong command" << endl;
            } else {
                cout << msg_buffer << endl;
            }
        }
    }
    return 0;
}