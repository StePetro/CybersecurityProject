#include <jsoncpp/json/json.h>
#include <openssl/bio.h>
#include <openssl/rand.h>

#include <cstring>
#include <fstream>
#include <iostream>
#include <string>

#include "../Authenticated_Encription/gcm.h"
#include "../Certificate/certificate_verifier.h"
#include "../Game/Game.h"
#include "../Key_Exchange/DHKE.h"
#include "../Nonce/nonce_operations.h"
#include "../Signature/signer.h"
#include "../Socket/peer_client.h"
#include "../Socket/peer_server.h"

#define SERVER_PORT 8080
#define IP_SERVER "172.16.1.213"
#define CERT_SAVE_PATH "PEM/ServerToClientCert.pem"
#define CA_CERT "PEM/ca_certificate.pem"
#define CRL "PEM/crl.pem"

using namespace std;

int play_server(PeerServerConnection &psc, unsigned char *session_key, unsigned char *msg_buffer) {
    cout << "Start of the game!" << endl;

    // Il nonce parte da 0
    unsigned char *nonce = new unsigned char[NONCE_SIZE];
#pragma optimize("", off)
    memset(nonce, 0, NONCE_SIZE);
#pragma optimize("", on)

    unsigned char *decrypted_msg;
    unsigned int decrypted_msg_len;

    Game g;
    char **board = g.createBoard();
    size_t column;
    size_t bytes_read;

    g.printBoard(board);

    while (true) {
        cout << "Waiting adversary move..." << endl;
        // ricevi mossa avversario
        if ((bytes_read = psc.read_msg((unsigned char *)msg_buffer)) == 0) {
            cerr << "Adversary disconnected" << endl;
            return -1;
        }

        nonce_add_one(nonce);
        if (memcmp(msg_buffer + IV_LEN, nonce, NONCE_SIZE) != 0) {
            cerr << "Wrong nonce, aborting connection..." << endl;
            return -1;
        }

        if (gcm_decrypt((unsigned char *)msg_buffer, bytes_read, NONCE_SIZE, session_key, decrypted_msg, decrypted_msg_len) != 0) {
            cerr << "A problem has occurred while decrypting the message. \n Aborting connection..." << endl;
            return -1;
        }

        memcpy(&column, decrypted_msg, decrypted_msg_len);

        // inseriscila nel campo
        if (!g.insertPiece(board, 'X', column)) {
            cout << "Received invalid move" << endl;
            return -1;
        }

        g.printBoard(board);

        if (g.checkWin(board, 'X')) {
            cout << "Ha vinto l'avversario" << endl;
            break;
        }
        if (g.isBoardFull(board)) {
            cout << "Pareggio" << endl;
            break;
        }

        // sfidato
        column = g.nextMove(board, 'O');
        g.printBoard(board);

        // invia colonna mossa
        memcpy(msg_buffer, &column, sizeof(size_t));
        unsigned char *final_msg;
        unsigned int final_msg_len;
        nonce_add_one(nonce);
        gcm_encrypt(msg_buffer, sizeof(size_t), nonce, NONCE_SIZE, session_key, final_msg, final_msg_len);
        if (psc.send_msg(final_msg, final_msg_len) != 0) {
            cout << "Send Error" << endl;
            return -1;
        }

        if (g.checkWin(board, 'O')) {
            cout << "Hai vinto" << endl;
            break;
        }
        if (g.isBoardFull(board)) {
            cout << "Pareggio" << endl;
            break;
        }
    }

    cout << "Chiusura gioco..." << endl;

    g.deleteBoard(board);

    return 0;
}

int play_client(PeerClientConnection &pcc, unsigned char *session_key, unsigned char *msg_buffer) {
    cout << "Start of the game!" << endl;

    Game g;
    char **board = g.createBoard();
    size_t column;
    size_t bytes_read;
    unsigned char *nonce = new unsigned char[NONCE_SIZE];
    unsigned char *encrypted_buff;
    unsigned char *decrypted_msg;
    unsigned int decrypted_msg_len;

#pragma optimize("", off)
    memset(nonce, 0, NONCE_SIZE);
#pragma optimize("", on)

    g.printBoard(board);

    while (true) {
        // sfidato
        column = g.nextMove(board, 'X');
        g.printBoard(board);

        // invia colonna mossa
        memcpy(msg_buffer, &column, sizeof(size_t));
        unsigned char *final_msg;
        unsigned int final_msg_len;
        nonce_add_one(nonce);
        gcm_encrypt(msg_buffer, sizeof(size_t), nonce, NONCE_SIZE, session_key, final_msg, final_msg_len);
        if (pcc.send_msg(final_msg, final_msg_len) != 0) {
            cout << "Send Error" << endl;
            return -1;
        }

        if (g.checkWin(board, 'X')) {
            cout << "Hai vinto" << endl;
            break;
        }
        if (g.isBoardFull(board)) {
            cout << "Pareggio" << endl;
            break;
        }
        cout << "Waiting adversary move..." << endl;
        // ricevi mossa avversario
        if ((bytes_read = pcc.read_msg(msg_buffer)) == 0) {
            cerr << "Adversary disconnected" << endl;
            return -1;
        }

        nonce_add_one(nonce);
        if (memcmp(msg_buffer + IV_LEN, nonce, NONCE_SIZE) != 0) {
            cerr << "Wrong nonce, aborting connection..." << endl;
            return -1;
        }

        if (gcm_decrypt((unsigned char *)msg_buffer, bytes_read, NONCE_SIZE, session_key, decrypted_msg, decrypted_msg_len) != 0) {
            cerr << "A problem has occurred while decrypting the message. \n Aborting connection..." << endl;
            return -1;
        }

        
        memcpy(&column, decrypted_msg, decrypted_msg_len);

        // inseriscila nel campo
        if (!g.insertPiece(board, 'O', column)) {
            cout << "Received invalid move" << endl;
            return -1;
        }

        g.printBoard(board);

        if (g.checkWin(board, 'O')) {
            cout << "Ha vinto l'avversario" << endl;
            break;
        }
        if (g.isBoardFull(board)) {
            cout << "Pareggio" << endl;
            break;
        }
    }

    cout << "Chiusura gioco..." << endl;

    g.deleteBoard(board);

    return 0;
}

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

int login_handler(string &pkey_path, unsigned char *msg_buffer, PeerClientConnection &cc, unsigned char *&session_key_server, string user) {
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

        pkey_path = users[user]["priv_key"].asString();

        // Firma: sig(nonce_s)
        if (sign(pkey_path, nonce_s, NONCE_SIZE, signed_msg, signed_msg_size) != 0) {
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
            if (sign(pkey_path, (unsigned char *)msg_buffer + sizeof(uint32_t), NONCE_SIZE + public_key_client_buf_size, signed_msg, signed_msg_size) != 0) {
                cerr << "Not able to sign" << endl;
                return -1;
            }

            // ( sgn_len || nonce_s || pubk_c)
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

// Key exchange for the client

int session_key_peer_client_negotiation(string pkey_path, unsigned char *&session_key_peer, unsigned char *IP_challenger, EVP_PKEY *pubkey_challenger, unsigned char *msg_buffer, PeerClientConnection &pcc) {
    unsigned int bytes_read;

    // Mi deve arrivare (sgn_size || nonce_s || pubk_s || sgn(pubk_s))
    if ((bytes_read = pcc.read_msg(msg_buffer)) == 0) {
        cerr << "Peer disconnected" << endl;
        return -1;
    }

    cout << msg_buffer << endl;

    uint32_t size_sign_pubk_s = 0;
    // recupero size della firma (sgn_size || nonce_s || pubk_s || sgn(pubk_s)
    memcpy(&size_sign_pubk_s, msg_buffer, sizeof(uint32_t));

    unsigned char *nonce_c = new unsigned char[NONCE_SIZE];
    unsigned char *nonce_s = new unsigned char[NONCE_SIZE];

    // recupero nonce server (sgn_size || nonce_s || pubk_s || sgn(pubk_s)
    memcpy(nonce_s, msg_buffer + sizeof(uint32_t), NONCE_SIZE);

    EVP_PKEY *public_key_server = NULL;  // solo chiave pubblica del server
    unsigned int public_key_server_buf_size = bytes_read - NONCE_SIZE - sizeof(uint32_t) - size_sign_pubk_s;
    unsigned char *public_key_server_buf = new unsigned char[public_key_server_buf_size];

    //(sgn_size || nonce_s || pubk_s || sgn(pubk_s)
    memcpy(public_key_server_buf, msg_buffer + sizeof(uint32_t) + NONCE_SIZE, public_key_server_buf_size);

    deserialize_pub_key(public_key_server_buf, public_key_server_buf_size, public_key_server);

    // Controlla la firma, chiude la connessione se sbagliata buffer = (sgn_len || nonce_c || pubk_s || sgn(pubk_s))
    if (verify_sign(pubkey_challenger, public_key_server_buf, public_key_server_buf_size, msg_buffer + bytes_read - size_sign_pubk_s, size_sign_pubk_s) != 0) {
        cerr << "Wrong signature" << endl;
        return -1;
    }

    // genero nonce client
    RAND_poll();
    RAND_bytes((unsigned char *)&nonce_c[0], NONCE_SIZE);

    //INIZIO COPIA
    EVP_PKEY *keys_client = NULL;  // Sia privata che pubblica
    unsigned char *public_key_client_buf = NULL;
    unsigned int public_key_client_buf_size;

    // Creazione chiavi effimere da parametri standard
    if (create_ephemeral_keys(keys_client) != 0) {
        cerr << "Error in parameters' creation" << endl;
        return -1;
    }

    uint32_t size_sign_pubk_c = 0;

    // (sgn_len || nonce_c || pub_key_c || sgn(nonce_s || pub_key_c) )

    // Serializzazione chiave pubblica client in un buffer
    if (serialize_pub_key(keys_client, public_key_client_buf, public_key_client_buf_size) != 0) {
        cerr << "Error in parameters' creation" << endl;
        return -1;
    }

    // (nonce_s || pub_key_c)
    memcpy(msg_buffer, nonce_s, NONCE_SIZE);
    memcpy(msg_buffer + NONCE_SIZE, public_key_client_buf, public_key_client_buf_size);

    // firmare sgn(nonce_s || pub_key_c)
    unsigned char *signed_buff;
    unsigned int signed_len = 0;
    if (sign(pkey_path, (unsigned char *)msg_buffer, NONCE_SIZE + public_key_client_buf_size, signed_buff, signed_len) != 0) {
        cerr << "Not able to sign" << endl;
        return -1;
    }

    // (sgn_len || nonce_c || pub_key_c || signed buff )
    memcpy(msg_buffer, &signed_len, sizeof(uint32_t));
    memcpy(msg_buffer + sizeof(uint32_t), nonce_c, NONCE_SIZE);
    memcpy(msg_buffer + sizeof(uint32_t) + NONCE_SIZE, public_key_client_buf, public_key_client_buf_size);
    memcpy(msg_buffer + sizeof(uint32_t) + NONCE_SIZE + public_key_client_buf_size, signed_buff, signed_len);
    if (pcc.send_msg(msg_buffer, sizeof(uint32_t) + NONCE_SIZE + public_key_client_buf_size + signed_len) != 0) {
        return -1;
    }

    // lettura nonce_c firmato
    if ((bytes_read = pcc.read_msg(msg_buffer)) == 0) {
        cerr << "Peer disconnected" << endl;
        return -1;
    }

    BIO_dump_fp(stdout, (const char *)msg_buffer, bytes_read);

    // verifica nonce_c
    if (verify_sign(pubkey_challenger, nonce_c, NONCE_SIZE, msg_buffer, bytes_read) != 0) {
        cerr << "Wrong signature" << endl;
        return -1;
    }

    // Deserializza la chiave pubblica effimera del server
    EVP_PKEY *pub_key_server = NULL;
    deserialize_pub_key((unsigned char *)public_key_server_buf, public_key_server_buf_size, pub_key_server);

    // Calcola la chiave di sessione
    if (derive_session_key(keys_client, pub_key_server, session_key_peer) != 0) {
        cerr << "Session key cannot be derived" << endl;
        return -1;
    }

    delete[] public_key_server_buf;
    delete[] nonce_c;
    delete[] nonce_s;

    return 0;
}

// FIND ------------------------------------------------------------------------------------------------------------------------------

int find_handler(string pkey_path, unsigned char *msg_buffer, PeerClientConnection &cc, unsigned char *session_key_server, unsigned char *nonce_server) {
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

    unsigned char *final_msg;
    unsigned int final_msg_len;

    if (response.compare("y") == 0) {
        // Challenge accettata

        // Invio y
        nonce_add_one(nonce_server);
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
        // Se il nonce è sbagliato chiude la connessione
        if (memcmp(msg_buffer + IV_LEN, nonce_server, NONCE_SIZE) != 0) {
            cerr << "Wrong nonce, aborting connection" << endl;
            exit(-1);
        }

        //(lunghezza indirizzo || IP || PEM pubkey)
        uint32_t ip_size = 0;
        memcpy(&ip_size, decrypted_msg, sizeof(uint32_t));

        cout << ip_size << endl;

        // ALLOCARE STRINGA IP E BUFFER PER PEM
        unsigned char *IP_challenger = new unsigned char[ip_size + 1];
        EVP_PKEY *pubkey_challenger;

        unsigned int size_PEM = bytes_read - sizeof(uint32_t) - ip_size;
        unsigned char *PEM_pubkey_challenger = new unsigned char[size_PEM];

        memcpy(IP_challenger, decrypted_msg + sizeof(uint32_t), ip_size);
        memcpy(PEM_pubkey_challenger, decrypted_msg + sizeof(uint32_t) + ip_size, size_PEM);

        IP_challenger[ip_size] = '\0';
        //deserializzo il pem
        deserialize_pub_key(PEM_pubkey_challenger, size_PEM, pubkey_challenger);

        //INIZIO PARTITA_____

        unsigned char *session_key_peer;

        // Per sicurezza, in modo che il server vada prima in ascolto
        sleep(1);

        PeerClientConnection pcc;
        pcc.initialization((const char *)IP_challenger, PORT_PEER_SERVER);

        if (session_key_peer_client_negotiation(pkey_path, session_key_peer, IP_challenger, pubkey_challenger, msg_buffer, pcc) != 0) {
            cerr << "Error in negotiating session key with peer" << endl;
            return -1;
        }

        if(play_client(pcc, session_key_peer, msg_buffer) != 0){
            return -1;
        }
    }
    // if the response is no the user goes back in the main loop
    if (response.compare("n") == 0) {
        // Invio n
        nonce_add_one(nonce_server);
        gcm_encrypt((unsigned char *)response.c_str(), response.length(), nonce_server, NONCE_SIZE, session_key_server, final_msg, final_msg_len);
        cc.send_msg(final_msg, final_msg_len);
        return -1;
    }
    return 1;
}

// Negoziazione chiave di sessione tra peer, lato peer-server ------------------------------------------------------------------------------------------------------
int session_key_peer_server_negotiation(PeerServerConnection &psc, string pkey_path, unsigned char *&session_key, EVP_PKEY *pubkey_challenged, unsigned char *msg_buffer) {
    unsigned int bytes_read;
    unsigned char *nonce_s = new unsigned char[NONCE_SIZE];
    unsigned char *nonce_c = new unsigned char[NONCE_SIZE];

    // Inizializzazione nonce server
    RAND_poll();
    RAND_bytes((unsigned char *)&nonce_s[0], NONCE_SIZE);

    EVP_PKEY *keys_server = NULL;  // Sia privata che pubblica
    unsigned char *public_key_server_buf = NULL;
    unsigned int public_key_server_buf_size;

    // Creazione chiavi effimere da parametri standard
    if (create_ephemeral_keys(keys_server) != 0) {
        cerr << "Error in parameters' creation" << endl;
        return -1;
    }

    // Serializzazione chiave pubblica server in un buffer
    if (serialize_pub_key(keys_server, public_key_server_buf, public_key_server_buf_size) != 0) {
        cerr << "Error in parameters' creation" << endl;
        return -1;
    }

    // ( sgn_size || nonce_s || pubk_s || sgn(pubk_s))

    // ( _____ || nonce_s || pubk_s || _____ ) <-- per ora ho messo
    memcpy(msg_buffer + sizeof(uint32_t), nonce_s, NONCE_SIZE);
    memcpy(msg_buffer + sizeof(uint32_t) + NONCE_SIZE, public_key_server_buf, public_key_server_buf_size);

    // Firma digitale di (pubk_s) (nel buffer)
    unsigned char *signed_buff;
    unsigned int signed_len = 0;
    // buff = ( _____ || nonce_s || pubk_s || _____ )
    if (sign(pkey_path, (unsigned char *)msg_buffer + sizeof(uint32_t) + NONCE_SIZE, public_key_server_buf_size, signed_buff, signed_len) != 0) {
        cerr << "Not able to sign" << endl;
        return -1;
    }

    // ( sgn_len || nonce_c || pubk_s || _____)
    cout << signed_len << endl;
    memcpy(msg_buffer, &signed_len, sizeof(uint32_t));

    // Invio messaggio = (sgn_len || nonce_c || pubk_s || sgn(nonce_c || pubk_s))
    memcpy(msg_buffer + sizeof(uint32_t) + NONCE_SIZE + public_key_server_buf_size, signed_buff, signed_len);
    if (psc.send_msg(msg_buffer, sizeof(uint32_t) + NONCE_SIZE + public_key_server_buf_size + signed_len) != 0) {
        return -1;
    }

    // Ricezione messaggio = (sgn_len || nonce_c || pubk_c || sgn(nonce_s || pubk_c))
    if ((bytes_read = psc.read_msg(msg_buffer)) == 0) {
        cerr << "Peer disconnected" << endl;
        return -1;
    }

    // Prelevo la dimensione della firma
    uint32_t sgn_len = 0;
    memcpy(&sgn_len, msg_buffer, sizeof(uint32_t));

    // prelievo nonce
    memcpy(nonce_c, msg_buffer + sizeof(uint32_t), NONCE_SIZE);

    // prelievo pubk_c
    unsigned int pubk_c_len = bytes_read - sgn_len - sizeof(uint32_t) - NONCE_SIZE;
    unsigned char *pubk_c_buffer = new unsigned char[pubk_c_len];
    memcpy(pubk_c_buffer, msg_buffer + NONCE_SIZE + sizeof(uint32_t), pubk_c_len);

    //(nonce_s || pubk_c)
    unsigned char *clear_buff = new unsigned char[pubk_c_len + NONCE_SIZE];
    memcpy(clear_buff, nonce_s, NONCE_SIZE);
    memcpy(clear_buff + NONCE_SIZE, pubk_c_buffer, pubk_c_len);

    // Controlla la firma, chiude la connessione se sbagliata, buff = (sgn_len || nonce_c || pubk_c || sgn(nonce_s || pubk_c))
    if (verify_sign(pubkey_challenged, clear_buff, pubk_c_len + NONCE_SIZE, msg_buffer + sizeof(uint32_t) + NONCE_SIZE + pubk_c_len, sgn_len) != 0) {
        cerr << "Wrong signature" << endl;
        return -1;
    }

    // Firma nonce
    unsigned char *signed_nonce_c;
    unsigned int signed_nonce_c_len = 0;
    if (sign(pkey_path, nonce_c, NONCE_SIZE, signed_nonce_c, signed_nonce_c_len) != 0) {
        cerr << "Not able to sign" << endl;
        return -1;
    }

    if (psc.send_msg(signed_nonce_c, signed_nonce_c_len) != 0) {
        return -1;
    }

    // Deserializza la chiave pubblica effimera del client
    EVP_PKEY *pub_key_client = NULL;
    deserialize_pub_key((unsigned char *)pubk_c_buffer, pubk_c_len, pub_key_client);

    // Calcola la chiave di sessione
    if (derive_session_key(keys_server, pub_key_client, session_key) != 0) {
        cerr << "Session key cannot be derived" << endl;
        return -1;
    }

    // iniziare partita

    cout << "FIN QUI TUTTO BENE" << endl;

    // Dealloco i nonce
    delete[] clear_buff;
    delete[] nonce_s;
    delete[] nonce_c;
    return 0;
}

// CHALLENGE ------------------------------------------------------------------------------------------------------------------------------

int challenge_handler(string pkey_path, unsigned char *msg_buffer, PeerClientConnection &cc, unsigned char *session_key_server, unsigned char *nonce_server) {
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
    string na = "NA";
    if ((na.compare(0, na.length(), (const char *)decrypted_msg) == 0)) {
        cout << "Challenge not accepted" << endl;
        return -1;
    }

    // massaggio (lunghezza indirizzo || IP || PEM pubkey)
    uint32_t ip_size = 0;
    memcpy(&ip_size, decrypted_msg, sizeof(uint32_t));

    // ALLOCARE STRINGA IP E BUFFER PER PEM
    unsigned char *IP_challenged = new unsigned char[ip_size];
    EVP_PKEY *pubkey_challenged;

    unsigned int size_PEM = bytes_read - sizeof(uint32_t) - ip_size;
    unsigned char *PEM_pubkey_challenged = new unsigned char[size_PEM];

    memcpy(IP_challenged, decrypted_msg + sizeof(uint32_t), ip_size);
    memcpy(PEM_pubkey_challenged, decrypted_msg + sizeof(uint32_t) + ip_size, size_PEM);

    //deserializzo il pem
    deserialize_pub_key(PEM_pubkey_challenged, size_PEM, pubkey_challenged);

    cout << "ip size letto " << ip_size << endl;

    cout << "ip letto " << endl;
    BIO_dump_fp(stdout, (const char *)IP_challenged, ip_size);
    cout << "size ip " << ip_size << endl;
    cout << "pem letto " << endl;
    BIO_dump_fp(stdout, (const char *)PEM_pubkey_challenged, size_PEM);

    cout << "pem size " << size_PEM << endl;

    // Scambio chiavi  -----------------------------------------------------------------------------------

    unsigned char *session_key;

    // Connessione con l'altro peer
    PeerServerConnection psc;
    psc.initialization();

    if (session_key_peer_server_negotiation(psc, pkey_path, session_key, pubkey_challenged, msg_buffer) != 0) {
        cerr << "Error in negotiating session key with peer" << endl;
        return -1;
    }

    // Inizio partita -----------------------------------------------------------------------------------

    if (play_server(psc, session_key, msg_buffer) != 0){
        return -1;
    }

    return 0;
}