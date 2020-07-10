#include <openssl/bio.h>
#include <openssl/rand.h>

#include <cstring>
#include <iostream>

#include "Certificate/certificate_verifier.h"
#include "Signature/signer.h"
#include "Socket/peer_client.h"
#include "Socket/peer_server.h"

#define SERVER_PORT 8080
#define IP_SERVER "172.16.1.213"
#define NONCE_SIZE 128
#define CERT_SAVE_PATH "PEM/ServerToClientCert.pem"
#define CA_CERT "PEM/ca_certificate.pem"
#define CRL "PEM/crl.pem"

using namespace std;

// Unsigned int a 128 bit, presente solo su alcuni compilatori
typedef unsigned __int128 uint128_t;

int cert_handler(unsigned char *msg_buffer, PeerClientConnection &cc) {
    // Gestisce la verifica del certificato se richiesta

    long bytes_read = 0;

    // Lettura lunghezza certificato + certificato
    if ((bytes_read = cc.read_msg(msg_buffer)) == 0) {
        cout << "Server disconnected" << endl;
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
        cout << "Certificate NOT valid, aborting connection..." << endl;
        exit(1);
    }

    return 0;
}

int login_handler(unsigned char *msg_buffer, PeerClientConnection &cc) {
    long bytes_read = 0;

    // Lettura risposta server alla /login:[nome_utente]
    if ((bytes_read = cc.read_msg(msg_buffer)) == 0) {
        cout << "Server disconnected" << endl;
        exit(1);
    }

    // Utente non trovato
    string tmp = "NF";
    if (strncmp((const char *)msg_buffer, tmp.c_str(), tmp.length()) == 0) {
        cout << "User not found" << endl;
        return -1;
    }

    // Utente non trovato
    tmp = "AL";
    if (strncmp((const char *)msg_buffer, tmp.c_str(), tmp.length()) == 0) {
        cout << "User already logged" << endl;
        return -1;
    }

    // Utente valido
    tmp = "ACK";
    if (strncmp((const char *)msg_buffer, tmp.c_str(), tmp.length()) == 0) {
        cout << "Authenticating..." << endl;

        // Generazione nonce client casuale
        RAND_poll();
        unsigned char *nonce_c = new unsigned char[NONCE_SIZE];
        RAND_bytes((unsigned char *)&nonce_c[NONCE_SIZE], NONCE_SIZE);

        // Mando nonce_c
        if (cc.send_msg(nonce_c, NONCE_SIZE) != 0) {
            return -1;
        }

        // Lettura risposta server
        // messaggio = (nonces || sig(noncec))
        if ((bytes_read = cc.read_msg(msg_buffer)) == 0) {
            cout << "Server disconnected" << endl;
            return -1;
        }

        // Verifico sig(noncec) con il certificato del server
        CertificateVerifier cv;
        if (cv.verify_signed_file(msg_buffer + NONCE_SIZE, bytes_read - NONCE_SIZE, nonce_c, NONCE_SIZE, CERT_SAVE_PATH) == 1) {
            cout << "Correct server signature" << endl;
        } else {
            return -1;
        }

        // Preparazione firma nonce_server
        unsigned char *signed_msg;
        unsigned int signed_msg_size;
        string private_key_path;
        cout << "Please insert your private key path: ";
        cin >> private_key_path;

        // Firma: sig(nonces)
        if (sign(private_key_path, msg_buffer, NONCE_SIZE, signed_msg, signed_msg_size) != 0) {
            return -1;
        }

        // Invio sig(nonces)
        if (cc.send_msg(signed_msg, signed_msg_size) != 0) {
            return -1;
        }

        // Lettura risposta server alla firma del nonce
        if ((bytes_read = cc.read_msg(msg_buffer)) == 0) {
            cout << "Server disconnected" << endl;
            return -1;
        }

        // Firma del client non valida
        string tmp = "NV";
        if (strncmp((const char *)msg_buffer, tmp.c_str(), tmp.length()) == 0) {
            cout << "Your signatur is not valid" << endl;
            return -1;
        }

        // Firma del client valida
        tmp = "ACK";
        if (strncmp((const char *)msg_buffer, tmp.c_str(), tmp.length()) == 0) {
            // Salvo il nonce e svuoto la memoria
            delete[] signed_msg;
            cout << "Login completed successfully" << endl;
            delete[] nonce_c;
            return 0;
        }
    }
    return -1;
}

main(int argc, char const *argv[]) {
    // Strutture dati utili
    unsigned char msg_buffer[MSG_MAX_LEN] = {0};
    long bytes_read = 0;
    uint128_t nonce_with_server = 0;
    uint128_t nonce_with_peer = 0;

    // Socket client
    PeerClientConnection cc;
    cc.initialization(IP_SERVER, SERVER_PORT);

    // Lettura messaggio benvenuto
    if ((bytes_read = cc.read_msg(msg_buffer)) == 0) {
        cout << "Server disconnected" << endl;
        exit(1);
    }
    printf("%s\n", msg_buffer);

    while (true) {
        // Scrittura verso server
        string msg;
        cout << "\nPlease type a command: ";
        cin >> msg;
        if (msg.compare("/exit") == 0 || msg.compare("/quit") == 0) {
            // Chiudo la connessione ed esco
            cout << "Thanks for playing, goodbye!" << endl;
            break;
        }
        cc.send_msg(msg);

        // Gestione richiesta certificato
        if (msg.compare(0, string("/login:").size(), "/login:") == 0) {
            if (login_handler(msg_buffer, cc) != 0) {
                cout << "Login failed" << endl;
            }
            nonce_with_server = 0;
            continue;
        }

        // Gestione richiesta certificato
        if (msg.compare("/cert") == 0) {
            if (cert_handler(msg_buffer, cc) != 0) {
                cout << "Certificate NOT verified" << endl;
            }
            continue;
        }

        // Lettura risposta server di default
        if ((bytes_read = cc.read_msg(msg_buffer)) == 0) {
            cout << "Server disconnected" << endl;
            exit(-1);
        }
        printf("%s\n", msg_buffer);
    }
    return 0;
}