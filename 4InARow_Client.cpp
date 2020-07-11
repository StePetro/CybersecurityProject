#include <openssl/bio.h>
#include <openssl/rand.h>

#include <cstring>
#include <iostream>

#include "Authenticated_Encription/gcm.h"
#include "Certificate/certificate_verifier.h"
#include "Key_Exchange/DHKE.h"
#include "Nonce/nonce_operations.h"
#include "Signature/signer.h"
#include "Socket/peer_client.h"
#include "Socket/peer_server.h"

#define SERVER_PORT 8080
#define IP_SERVER "172.16.1.213"
#define NONCE_SIZE 16  // 128 bit
#define CERT_SAVE_PATH "PEM/ServerToClientCert.pem"
#define CA_CERT "PEM/ca_certificate.pem"
#define CRL "PEM/crl.pem"
#define PRIVATE_KEY_PATH "PEM/alice_private_key.pem"

using namespace std;

int cert_handler(unsigned char *msg_buffer, PeerClientConnection &cc) {
    // Gestisce la verifica del certificato se richiesta

    long bytes_read = 0;

    // Lettura lunghezza certificato + certificato
    if ((bytes_read = cc.read_msg(msg_buffer)) == 0) {
        cerr << "Server disconnected" << endl;
        exit(1);
    }

    // Apre il file dove salvare il certificato
    string cert_file_name = CERT_SAVE_PATH;
    FILE *cert_file = fopen(cert_file_name.c_str(), "wb");
    if (!cert_file) {
        cerr << "Error: cannot open file '" << cert_file_name << "' (no permissions?)\n";
        return -1;
    }

    // Salva il certificato nel file
    if (fwrite(msg_buffer, 1, bytes_read, cert_file) < bytes_read) {
        cerr << "Error while writing the file '" << cert_file_name << "'\n";
        return -1;
    }
    fclose(cert_file);

    // Permette di verificare il certificato
    CertificateVerifier cv;

    // Verifica il certificato
    if (cv.verify_server_certificate(cert_file_name, CA_CERT, CRL) == 1) {
        cout << "The certificate is valid" << endl;
        cout << "Server: " << cv.get_server_name() << endl;
        cout << "CA: " << cv.get_ca_name() << endl;
    } else {
        cerr << "Certificate NOT valid, aborting connection..." << endl;
        exit(1);
    }

    return 0;
}

int login_handler(unsigned char *msg_buffer, PeerClientConnection &cc, unsigned char *&session_key_server) {
    long bytes_read = 0;

    // Lettura risposta server alla /login:[nome_utente]
    if ((bytes_read = cc.read_msg(msg_buffer)) == 0) {
        cerr << "Server disconnected" << endl;
        exit(1);
    }

    // Utente non trovato
    string tmp = "NF";
    if (strncmp((const char *)msg_buffer, tmp.c_str(), tmp.length()) == 0) {
        cerr << "User not found" << endl;
        return -1;
    }

    // Utente non trovato
    tmp = "AL";
    if (strncmp((const char *)msg_buffer, tmp.c_str(), tmp.length()) == 0) {
        cerr << "User already logged" << endl;
        return -1;
    }

    // Utente valido
    tmp = "ACK";
    if (strncmp((const char *)msg_buffer, tmp.c_str(), tmp.length()) == 0) {
        cout << "Authenticating..." << endl;

        // Generazione nonce_c del client casuale
        RAND_poll();
        unsigned char *nonce_c = new unsigned char[NONCE_SIZE];
        RAND_bytes((unsigned char *)&nonce_c[0], NONCE_SIZE);

        // Mando nonce_c
        if (cc.send_msg(nonce_c, NONCE_SIZE) != 0) {
            return -1;
        }

        // Lettura risposta server
        // messaggio = (nonces || sig(noncec))
        if ((bytes_read = cc.read_msg(msg_buffer)) == 0) {
            cerr << "Server disconnected" << endl;
            return -1;
        }

        // Salvo nonce_s in un buffer
        unsigned char *nonce_s = new unsigned char[NONCE_SIZE];
        memcpy(nonce_s, msg_buffer, NONCE_SIZE);

        // Verifico sig(noncec) con il certificato del server
        CertificateVerifier cv;
        if (cv.verify_signed_file(msg_buffer + NONCE_SIZE, bytes_read - NONCE_SIZE, nonce_c, NONCE_SIZE, CERT_SAVE_PATH) == 1) {
            cout << "Correct server signature" << endl;
        } else {
            return -1;
        }

        // Preparazione firma nonce_server
        unsigned char *signed_msg;
        uint32_t signed_msg_size = 0;

        // Firma: sig(nonce_s)
        if (sign(PRIVATE_KEY_PATH, nonce_s, NONCE_SIZE, signed_msg, signed_msg_size) != 0) {
            return -1;
        }

        // Invio sig(nonce_s)
        if (cc.send_msg(signed_msg, signed_msg_size) != 0) {
            return -1;
        }

        delete[] signed_msg;

        // Lettura risposta server alla firma del nonce
        if ((bytes_read = cc.read_msg(msg_buffer)) == 0) {
            cerr << "Server disconnected" << endl;
            return -1;
        }

        // Firma del client non valida
        string tmp = "NV";
        if (strncmp((const char *)msg_buffer, tmp.c_str(), tmp.length()) == 0) {
            cerr << "Your signatur is not valid" << endl;
            return -1;
        }

        // Firma del client valida
        tmp = "ACK";
        if (strncmp((const char *)msg_buffer, tmp.c_str(), tmp.length()) == 0) {
            //INIZIO NEGOZIAZIONE CHIAVE DI SESSIONE -------------------------------------------------------------------------
            EVP_PKEY *keys_client = NULL;  // Sia privata che pubblica
            unsigned char *public_key_client_buf = NULL;
            unsigned int public_key_client_buf_size;

            // Creazione chiavi effimere da parametri standard
            if (create_ephemeral_keys(keys_client) != 0) {
                cerr << "Error in parameters' creation" << endl;
                return -1;
            }

            // Serializzazione chiave pubblica client in un buffer
            if (serialize_pub_key(keys_client, public_key_client_buf, public_key_client_buf_size) != 0) {
                cerr << "Error in parameters' creation" << endl;
                return -1;
            }

            // Incremento di 1 i due nonce
            nonce_add_one(nonce_s);
            nonce_add_one(nonce_c);

            // Ricezione messaggio = (sgn_len || nonce_c || pubk_s || sgn(nonce_c || pubk_s))
            if ((bytes_read = cc.read_msg(msg_buffer)) == 0) {
                cerr << "Server disconnected" << endl;
                return -1;
            }

            // Se il nonce è sbagliato chiude la connessione
            if (memcmp(msg_buffer + sizeof(uint32_t), nonce_c, NONCE_SIZE) != 0) {
                cerr << "Wrong nonce" << endl;
                return -1;
            }

            // Prelevo la dimensione della firma
            uint32_t SGN_SIZE = 0;
            memcpy(&SGN_SIZE, msg_buffer, sizeof(uint32_t));
            cout << SGN_SIZE << endl;

            // Controlla la firma, chiude la connessione se sbagliata buffer = (sgn_len || nonce_c || pubk_s || sgn(nonce_c || pubk_s))
            if (cv.verify_signed_file(msg_buffer + bytes_read - SGN_SIZE, SGN_SIZE, msg_buffer + sizeof(uint32_t), bytes_read - SGN_SIZE - +sizeof(uint32_t), CERT_SAVE_PATH) != 1) {
                cerr << "Wrong signature" << endl;
                return -1;
            }

            // Deserializza la chiave pubblica effimera del client
            EVP_PKEY *pub_key_server = NULL;
            if (deserialize_pub_key((unsigned char *)msg_buffer + NONCE_SIZE + sizeof(uint32_t), bytes_read - SGN_SIZE - NONCE_SIZE - sizeof(uint32_t), pub_key_server) != 0) {
                cerr << "Key deserialization failed" << endl;
                return -1;
            }

            // Calcola la chiave di sessione
            if (derive_session_key(keys_client, pub_key_server, session_key_server) != 0) {
                cerr << "Session key cannot be derived" << endl;
                return -1;
            }

            // ( _____ || nonce_s || pubk_c)
            memcpy(msg_buffer + sizeof(uint32_t), nonce_s, NONCE_SIZE);
            memcpy(msg_buffer + sizeof(uint32_t) + NONCE_SIZE, public_key_client_buf, public_key_client_buf_size);

            // Firma digitale di (nonce_s || pubk_c) (nel buffer)
            signed_msg_size = 0;
            if (sign(PRIVATE_KEY_PATH, (unsigned char *)msg_buffer + sizeof(uint32_t), NONCE_SIZE + public_key_client_buf_size, signed_msg, signed_msg_size) != 0) {
                cerr << "Not able to sign" << endl;
                return -1;
            }

            // ( sgn_len || nonce_s || pubk_c)
            cout << signed_msg_size << endl;
            memcpy(msg_buffer, &signed_msg_size, sizeof(uint32_t));

            // Invio messaggio = (sgn_len || nonce_s || pubk_c || sgn(nonce_s || pubk_c))
            memcpy(msg_buffer + sizeof(uint32_t) + NONCE_SIZE + public_key_client_buf_size, signed_msg, signed_msg_size);
            BIO_dump_fp(stdout, (const char *)msg_buffer, sizeof(uint32_t) + NONCE_SIZE + public_key_client_buf_size + signed_msg_size);
            BIO_dump_fp(stdout, (const char *)nonce_c, NONCE_SIZE);
            if (cc.send_msg(msg_buffer, sizeof(uint32_t) + NONCE_SIZE + public_key_client_buf_size + signed_msg_size) != 0) {
                cerr << "Error in sending the message" << endl;
                return -1;
            }

            // Salvo il nonce e svuoto la memoria
            cout << "Login completed successfully" << endl;
            delete[] signed_msg;
            delete[] nonce_c;
            delete[] nonce_s;

            return 0;
        }
    }
    return -1;
}


// DA FINIRE E TESTARE
int find_challenger_handler(unsigned char* msg_buffer, PeerClientConnection &cc){
    // gestisce la ricerca di uno sfidante
    
    long bytes_read = 0;
    unsigned char* challenger;

    // Lettura lunghezza certificato + certificato
    if ((bytes_read = cc.read_msg(msg_buffer)) == 0) {
        cout << "Server disconnected" << endl;
        exit(1);
    }
    // messaggio da decryptare
    
    string base_msg = "/challenge:";
    size_t len_base_msg = base_msg.length();
    if (strncmp((const char *)msg_buffer, base_msg.c_str(), len_base_msg) == 0) {

        //strncpy(dest, src + beginIndex, endIndex - beginIndex);
        //strncpy((char*)challenger, (char*)(msg_buffer + len_base_msg), bytes_read - len_base_msg);

        //cout << "I'm being challenged by " << challenger << endl;

        cout << "I have received: " << msg_buffer << endl;
        string response;
        cout << "\nDo you accept the challenge? (y/n)" << endl;
        while(true){
            cin >> response;
            if(response.compare("y") == 0 || response.compare("n") == 0){ // a valid response has been given
                break;
            }
            cout << "Please type a valid command. (y/n)" << endl;
            response.empty();
        }
        
        if(response.compare("y") == 0){
            // send the response
            cc.send_msg(response.c_str());

            
            // wait for data of the challenger
            if ((bytes_read = cc.read_msg(msg_buffer)) == 0) {
            cout << "Server disconnected" << endl;
            exit(1);
            }
            
            cout << "I have received: " << msg_buffer << endl;
            
            /*
            // COME FACCIO A SAPERE LA LUNGHEZZA DELL'IP?
            size_t len_ip;

            // ALLOCARE STRINGA IP E BUFFER PER PEM
            unsigned char* IP_challenger;
            unsigned char* PEM_pubkey_challenger;
            EVP_PKEY* pubkey_challenger;

            // ASSEGNO A OGNUNA DI ESSE LA GIUSTA PARTE DI msg_buffer
            //deserializzo il pem
            deserialize_pub_key(PEM_pubkey_challenger, bytes_read - len_ip, pubkey_challenger);

            //mi connetto allo sfidante 
            */
        }
        else {

            cc.send_msg(response.c_str());
            cout << "Ho rifiutato!" << endl;
        }
    // if the response is no the user goes back in the main loop

    }

}

// DA FARE
int challenge_handler(){}

// DA FARE
int list_handler(){}


main(int argc, char const *argv[]) {
    // Strutture dati utili
    char msg_buffer[MSG_MAX_LEN] = {0};
    long bytes_read = 0;
    unsigned char *session_key_server = NULL;
    unsigned char nonce_server[NONCE_SIZE] = {0};

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
        if (session_key_server != NULL) {
            nonce_add_one(nonce_server);
        }
        // Scrittura verso server
        string msg;
        cout << "\nPlease type a command: ";
        cin >> msg;
        if (msg.compare("/exit") == 0 || msg.compare("/quit") == 0) {
            // Chiudo la connessione ed esco
            cout << "Thanks for playing, goodbye!" << endl;
            break;
        }

        if (session_key_server != NULL) {
            // Comandi da loggato
            unsigned char *final_msg;
            unsigned int final_msg_len;
            gcm_encrypt((unsigned char *)msg.c_str(), msg.length(), nonce_server, NONCE_SIZE, session_key_server, final_msg, final_msg_len);
            cc.send_msg(final_msg, final_msg_len);
        } else {
            // Comandi da NON loggato
            cc.send_msg(msg);
        }

        // Gestione richiesta certificato
        if (msg.compare(0, string("/login:").size(), "/login:") == 0 && session_key_server == NULL) {
            if (login_handler((unsigned char *)msg_buffer, cc, session_key_server) != 0) {
                cerr << "Login failed" << endl;
                break;
            }
            continue;
        }

        // Gestione richiesta certificato
        if (msg.compare("/cert") == 0) {
            if (cert_handler((unsigned char *)msg_buffer, cc) != 0) {
                cerr << "Certificate NOT verified" << endl;
            }
            continue;
        }

        // Gestione richiesta di cercare uno sfidante
        if(msg.compare("/find_challenger") == 0){
            cout << "I'm looking for a challenger" << endl;
            find_challenger_handler((unsigned char*) msg_buffer, cc);

            continue;
        }

        // Lettura risposta server di default
        if ((bytes_read = cc.read_msg((unsigned char *)msg_buffer)) == 0) {
            cerr << "Server disconnected" << endl;
            exit(-1);
        }

        // Incremento il nonce di 1
        if (session_key_server != NULL) {
            unsigned char *decrypted_msg;
            unsigned int decrypted_msg_len;
            gcm_decrypt((unsigned char *)msg_buffer, bytes_read, NONCE_SIZE, session_key_server, decrypted_msg, decrypted_msg_len);

            // Se il nonce è sbagliato chiude la connessione
            if (memcmp(msg_buffer + IV_LEN, nonce_server, NONCE_SIZE) != 0) {
                cerr << "Wrong nonce, aborting connection" << endl;
                break;
            }

            memcpy(msg_buffer, decrypted_msg, decrypted_msg_len);
            msg_buffer[decrypted_msg_len] = '\0';
            cout << msg_buffer << endl;
            nonce_add_one(nonce_server);
        } else {
            cout << msg_buffer << endl;
        }
    }
    return 0;
}