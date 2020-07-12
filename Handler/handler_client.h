#include <jsoncpp/json/json.h>
#include <openssl/bio.h>
#include <openssl/rand.h>

#include <cstring>
#include <fstream>
#include <iostream>

#include "../Authenticated_Encription/gcm.h"
#include "../Certificate/certificate_verifier.h"
#include "../Key_Exchange/DHKE.h"
#include "../Nonce/nonce_operations.h"
#include "../Signature/signer.h"
#include "../Socket/peer_client.h"
#include "../Socket/peer_server.h"

#define SERVER_PORT 8080
#define IP_SERVER "172.16.1.213"
#define NONCE_SIZE 16  // 128 bit
#define CERT_SAVE_PATH "PEM/ServerToClientCert.pem"
#define CA_CERT "PEM/ca_certificate.pem"
#define CRL "PEM/crl.pem"

using namespace std;

// CERTICATO ------------------------------------------------------------------------------------------------------------------------------

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

// LOGIN ------------------------------------------------------------------------------------------------------------------------------

int login_handler(unsigned char *msg_buffer, PeerClientConnection &cc, unsigned char *&session_key_server, string user) {
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

    // Utente già loggato
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

        // Prelevo il path della chiave privata salvato in un json per comodità
        Json::Value users;

        ifstream users_file("private_users.json", ifstream::binary);
        users_file >> users;

        // Firma: sig(nonce_s)
        if (sign(users[user]["priv_key"].asString(), nonce_s, NONCE_SIZE, signed_msg, signed_msg_size) != 0) {
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
            deserialize_pub_key((unsigned char *)msg_buffer + NONCE_SIZE + sizeof(uint32_t), bytes_read - SGN_SIZE - NONCE_SIZE - sizeof(uint32_t), pub_key_server);

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
            if (sign(users[user]["priv_key"].asString(), (unsigned char *)msg_buffer + sizeof(uint32_t), NONCE_SIZE + public_key_client_buf_size, signed_msg, signed_msg_size) != 0) {
                cerr << "Not able to sign" << endl;
                return -1;
            }

            // ( sgn_len || nonce_s || pubk_c)
            cout << signed_msg_size << endl;
            memcpy(msg_buffer, &signed_msg_size, sizeof(uint32_t));

            // Invio messaggio = (sgn_len || nonce_s || pubk_c || sgn(nonce_s || pubk_c))
            memcpy(msg_buffer + sizeof(uint32_t) + NONCE_SIZE + public_key_client_buf_size, signed_msg, signed_msg_size);
            //BIO_dump_fp(stdout, (const char *)msg_buffer, sizeof(uint32_t) + NONCE_SIZE + public_key_client_buf_size + signed_msg_size);
            //BIO_dump_fp(stdout, (const char *)nonce_c, NONCE_SIZE);
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

// FIND ------------------------------------------------------------------------------------------------------------------------------

int find_handler(unsigned char *msg_buffer, PeerClientConnection &cc, unsigned char *session_key_server, unsigned char *nonce_server) {
    // gestisce la ricerca di uno sfidante

    long bytes_read = 0;
    string challenger;

    // Lettura lunghezza pem
    if ((bytes_read = cc.read_msg(msg_buffer)) == 0) {
        cout << "Server disconnected" << endl;
        exit(1);
    }

    // messaggio da decryptare
    unsigned char *decrypted_msg;
    unsigned int decrypted_msg_len;
    if (gcm_decrypt((unsigned char *)msg_buffer, bytes_read, NONCE_SIZE, session_key_server, decrypted_msg, decrypted_msg_len) != 0) {
        cerr << "A problem has occurred while decrypting the message. \n Aborting connection..." << endl;
        exit(1);
    }

    // il nonce va incrementato ad ogni invio e ricezione di un nuovo messaggio, poi lo controlliamo
    nonce_add_one(nonce_server);

    // Se il nonce è sbagliato chiude la connessione
    if (memcmp(msg_buffer + IV_LEN, nonce_server, NONCE_SIZE) != 0) {
        cerr << "Wrong nonce, aborting connection" << endl;
        exit(1);
    }

    //Nome sfidante
    challenger = string((char *)decrypted_msg);

    cout << "I'm being challenged by: " << challenger << endl;

    string response;
    cout << "\nDo you accept the challenge? (y/n)" << endl;
    while (true) {
        cin >> response;
        if (response.compare("y") == 0 || response.compare("n") == 0) {  // a valid response has been given
            break;
        }
        cout << "Please type a valid command. (y/n)" << endl;
        response.empty();
    }

    if (response.compare("y") == 0) {
        // Challenge accettata
        unsigned char *final_msg;
        unsigned int final_msg_len;
        // il nonce va incrementato prima di inviare/ricevere un messaggio
        nonce_add_one(nonce_server);
        //cout << "Prima invio messaggio" << endl;
        //BIO_dump_fp(stdout, (const char *)nonce_server, NONCE_SIZE);
        gcm_encrypt((unsigned char *)response.c_str(), response.length(), nonce_server, NONCE_SIZE, session_key_server, final_msg, final_msg_len);
        cc.send_msg(final_msg, final_msg_len);

        // wait for data of the challenger
        if ((bytes_read = cc.read_msg(msg_buffer)) == 0) {
            cout << "Server disconnected" << endl;
            exit(1);
        }

        unsigned char *decrypted_msg;
        unsigned int decrypted_msg_len;
        if (gcm_decrypt((unsigned char *)msg_buffer, bytes_read, NONCE_SIZE, session_key_server, decrypted_msg, decrypted_msg_len) != 0) {
            cerr << "A problem has occurred while decrypting the message. \n Aborting connection..." << endl;
            exit(-1);
        }

        // il nonce va incrementato ad ogni invio e ricezione di un nuovo messaggio, poi lo controlliamo
        nonce_add_one(nonce_server);
        //cout << "Ricezione messaggio challenge" << endl;
        //BIO_dump_fp(stdout, (const char *)nonce_server, NONCE_SIZE);
        // Se il nonce è sbagliato chiude la connessione
        if (memcmp(msg_buffer + IV_LEN, nonce_server, NONCE_SIZE) != 0) {
            cerr << "Wrong nonce, aborting connection" << endl;
            exit(-1);
        }

        // COME FACCIO A SAPERE LA LUNGHEZZA DELL'IP? -> cambio formato del massaggio (lunghezza indirizzo || IP || PEM pubkey)
        uint32_t ip_size = 0;
        memcpy(&ip_size, decrypted_msg, sizeof(uint32_t));

        // ALLOCARE STRINGA IP E BUFFER PER PEM
        unsigned char *IP_challenger = new unsigned char[ip_size];
        EVP_PKEY *pubkey_challenger;

        unsigned int size_PEM = bytes_read - sizeof(uint32_t) - ip_size;
        unsigned char *PEM_pubkey_challenger = new unsigned char[size_PEM];

        memcpy(IP_challenger, decrypted_msg + sizeof(uint32_t), ip_size);
        memcpy(PEM_pubkey_challenger, decrypted_msg + sizeof(uint32_t) + ip_size, size_PEM);

        //deserializzo il pem
        deserialize_pub_key(PEM_pubkey_challenger, size_PEM, pubkey_challenger);

        //INIZIO PARTITA_____

        //mi connetto allo sfidante e dialogo per lo scambio delle chiavi di sessione
    }
    // if the response is no the user goes back in the main loop
    if (response.compare("n") == 0) {
        return -1;
    }
    return 1;
}

// CHALLENGE ------------------------------------------------------------------------------------------------------------------------------

int challenge_handler(unsigned char *msg_buffer, PeerClientConnection &cc, unsigned char *session_key_server, unsigned char *nonce_server) {
    unsigned int bytes_read;

    if ((bytes_read = cc.read_msg((unsigned char *)msg_buffer)) == 0) {
        cerr << "Server disconnected" << endl;
        exit(-1);
    }

    unsigned char *decrypted_msg;
    unsigned int decrypted_msg_len;
    if (gcm_decrypt((unsigned char *)msg_buffer, bytes_read, NONCE_SIZE, session_key_server, decrypted_msg, decrypted_msg_len) != 0) {
        cerr << "A problem has occurred while decrypting the message. \n Aborting connection..." << endl;
        exit(-1);
    }

    // il nonce va incrementato ad ogni invio e ricezione di un nuovo messaggio, poi lo controlliamo
    nonce_add_one(nonce_server);
    if (memcmp(msg_buffer + IV_LEN, nonce_server, NONCE_SIZE) != 0) {
        cerr << "Wrong nonce, aborting connection" << endl;
        exit(-1);
    }

    // massaggio (lunghezza indirizzo || IP || PEM pubkey)
    uint32_t ip_size = 0;
    memcpy(&ip_size, decrypted_msg, sizeof(uint32_t));

    // ALLOCARE STRINGA IP E BUFFER PER PEM
    unsigned char *IP_challenger = new unsigned char[ip_size];
    EVP_PKEY *pubkey_challenger;

    unsigned int size_PEM = bytes_read - sizeof(uint32_t) - ip_size;
    unsigned char *PEM_pubkey_challenger = new unsigned char[size_PEM];

    memcpy(IP_challenger, decrypted_msg + sizeof(uint32_t), ip_size);
    memcpy(PEM_pubkey_challenger, decrypted_msg + sizeof(uint32_t) + ip_size, size_PEM);

    //deserializzo il pem
    deserialize_pub_key(PEM_pubkey_challenger, size_PEM, pubkey_challenger);

    cout<< "ip size letto " << ip_size<< endl;


    cout<< "ip letto "<< endl;
    BIO_dump_fp(stdout, (const char*) IP_challenger, ip_size);
    cout<< "size ip " << ip_size << endl;
    cout<< "pem letto "<< endl;
    BIO_dump_fp(stdout, (const char*) PEM_pubkey_challenger, size_PEM);

cout<< "pem size " << size_PEM << endl;

    //INIZIO PARTITA_____

    //mi connetto allo sfidante e dialogo per lo scambio delle chiavi di sessione
}