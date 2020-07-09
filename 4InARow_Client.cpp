#include <openssl/bio.h>
#include <openssl/rand.h>

#include <iostream>

#include "Certificate/certificate_verifier.h"
#include "Signature/signer.h"
#include "Socket/peer_client.h"
#include "Socket/peer_server.h"

#define SERVER_PORT 8080
#define IP_SERVER "172.16.1.213"
#define NONCE_SIZE 4  //La stessa di un unsigned int
#define CERT_SAVE_PATH "PEM/ServerToClientCert.pem"
#define CA_CERT "PEM/ca_certificate.pem"
#define CRL "PEM/crl.pem"

using namespace std;

int cert_handler(unsigned char *msg_buffer, PeerClientConnection &cc) {
    // Gestisce la verifica del certificato se richiesta

    long bytes_read = 0;

    // Lettura lunghezza certificato + certificato
    if ((bytes_read = cc.read_msg(msg_buffer)) == 0) {
        cout << "Server disconnected" << endl;
        exit(1);
    }

    //BIO_dump_fp(stdout, (const char *)msg_buffer, MSG_MAX_LEN);

    //cout << cert_size << endl;

    string cert_file_name = CERT_SAVE_PATH;
    FILE *cert_file = fopen(cert_file_name.c_str(), "wb");
    if (!cert_file) {
        cerr << "Error: cannot open file '" << cert_file_name << "' (no permissions?)\n";
        return -1;
    }

    if (fwrite(msg_buffer, 1, bytes_read, cert_file) < bytes_read) {
        cerr << "Error while writing the file '" << cert_file_name << "'\n";
        return -1;
    }

    fclose(cert_file);

    CertificateVerifier cv;

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

int login_handler(unsigned char *msg_buffer, PeerClientConnection &cc, unsigned char *&nonce_s) {
    long bytes_read = 0;

    // Lettura risposta server
    if ((bytes_read = cc.read_msg(msg_buffer)) == 0) {
        cout << "Server disconnected" << endl;
        exit(1);
    }

    //printf("%s\n", msg_buffer);

    string tmp = "NF";
    if (strncmp((const char *)msg_buffer, tmp.c_str(), tmp.length()) == 0) {
        cout << "User not found" << endl;
        return -1;
    }

    tmp = "ACK";
    if (strncmp((const char *)msg_buffer, tmp.c_str(), tmp.length()) == 0) {
        cout << "Authenticating..." << endl;
        // Seed OpenSSL PRNG
        RAND_poll();
        // Generate nonce at random
        unsigned char *nonce_sc = (unsigned char *)malloc(NONCE_SIZE * 2);
        RAND_bytes((unsigned char *)&nonce_sc[NONCE_SIZE], NONCE_SIZE);

        // Mando solo noncec
        cc.send_msg(nonce_sc + NONCE_SIZE, NONCE_SIZE);

        //cout << "noncec" << endl;
        //BIO_dump_fp(stdout, (const char *)nonce_sc + NONCE_SIZE, NONCE_SIZE);

        // Lettura risposta server
        // messaggio = (nonces || sig(nonces||noncec))
        if ((bytes_read = cc.read_msg(msg_buffer)) == 0) {
            cout << "Server disconnected" << endl;
            return -1;
        }

        //cout << "(nonces || sig(nonces||noncec)" << endl;
        //BIO_dump_fp(stdout, (const char *)msg_buffer, bytes_read);

        // Giustappongo i due nonce: (nonces||noncec)
        memcpy(nonce_sc, msg_buffer, NONCE_SIZE);

        //cout << "(nonces||noncec)" << endl;
       // BIO_dump_fp(stdout, (const char *)nonce_sc, NONCE_SIZE * 2);

        //cout << "sig(nonces||noncec)" << endl;
        //BIO_dump_fp(stdout, (const char *)msg_buffer + NONCE_SIZE, bytes_read - NONCE_SIZE);

        CertificateVerifier cv;

        // Verifico sig(nonces||noncec)
        if (cv.verify_signed_file(msg_buffer + NONCE_SIZE, bytes_read - NONCE_SIZE, nonce_sc, NONCE_SIZE * 2, CERT_SAVE_PATH) == 1) {
            cout << "Correct server signature" << endl;
        } else {
            return -1;
        }

        unsigned char *signed_msg;
        unsigned int signed_msg_size;
        string private_key_path;
        cout << "Please insert your private key path: ";
        cin >> private_key_path;

        // sig(nonces)
        if(sign(private_key_path, nonce_sc, NONCE_SIZE, signed_msg, signed_msg_size) != 0){
            return -1;
        }

        // invio sig(nonces)
        cc.send_msg(signed_msg, signed_msg_size);

        // Lettura risposta server
        if ((bytes_read = cc.read_msg(msg_buffer)) == 0) {
            cout << "Server disconnected" << endl;
            return -1;
        }

        string tmp = "NV";
        if (strncmp((const char *)msg_buffer, tmp.c_str(), tmp.length()) == 0) {
            cout << "Your signatur is not valid" << endl;
            return -1;
        }

        tmp = "ACK";
        if (strncmp((const char *)msg_buffer, tmp.c_str(), tmp.length()) == 0) {
            free(signed_msg);
            cout << "Login completed" << endl;
            // Salvo il nonce e svuoto la memoria
            nonce_s = (unsigned char *)malloc(NONCE_SIZE);
            memcpy(nonce_s, nonce_sc, NONCE_SIZE);
            free(nonce_sc);
            return 0;
        }
    }
    return -1;
}

main(int argc, char const *argv[]) {
    unsigned char msg_buffer[MSG_MAX_LEN] = {0};
    long bytes_read = 0;
    unsigned char *nonce;

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
        cc.send_msg(msg.c_str());

        // Gestione richiesta certificato
        if (msg.compare("/cert") == 0) {
            if (!cert_handler(msg_buffer, cc) == 0) {
                cout << "Certificate NOT verified" << endl;
            }
            continue;
        }

        // Gestione richiesta certificato
        if (msg.compare(0, string("/login").size(), "/login") == 0) {
            if (!login_handler(msg_buffer, cc, nonce) == 0) {
                cout << "Login failed" << endl;
            }
            continue;
        }

        // Gestione richiesta certificato
        if (msg.compare("/exit") == 0 || msg.compare("/quit") == 0) {
            cout << "Thanks for playing, goodbye!" << endl;
            break;
        }

        // Lettura risposta server
        if ((bytes_read = cc.read_msg(msg_buffer)) == 0) {
            cout << "Server disconnected" << endl;
            exit(1);
        }
        printf("%s\n", msg_buffer);
    }
}