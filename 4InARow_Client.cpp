#include <openssl/bio.h>

#include <iostream>

#include "Socket/peer_client.h"
#include "Socket/peer_server.h"
#include "Certificate/certificate_verifier.h"

using namespace std;

main(int argc, char const *argv[]) {
    unsigned char msg_buffer[MSG_MAX_LEN] = {0};

    PeerClientConnection cc;
    cc.initialization("172.16.1.213", 8080);

    // Lettura messaggio benvenuto
    cc.read_msg(msg_buffer);
    printf("%s\n", msg_buffer);

    // Richiesta certificato
    cc.send_msg("/cert");

    // Lettura lunghezza certificato + certificato
    cc.read_msg(msg_buffer);
    BIO_dump_fp(stdout, (const char *)msg_buffer, MSG_MAX_LEN);

    long cert_size = 0;
    memcpy(&cert_size, msg_buffer, sizeof(long));

    cout << cert_size << endl;

    string cert_file_name = "PEM/ServerToClientCert.pem";
    FILE *cert_file = fopen(cert_file_name.c_str(), "wb");
    if (!cert_file) {
        cerr << "Error: cannot open file '" << cert_file_name << "' (no permissions?)\n";
        exit(1);
    }

    if (fwrite(msg_buffer + sizeof(long), 1, cert_size, cert_file) < cert_size) {
        cerr << "Error while writing the file '" << cert_file_name << "'\n";
        exit(1);
    }

    fclose(cert_file);

    CertificateVerifier cv;
    if(cv.verify_server_certificate(cert_file_name,"PEM/ca_certificate.pem","PEM/crl.pem") == 1){
        cout << "The certificate is valid" << endl;
        cout << "Server: " << cv.get_server_name() << endl;
        cout << "CA: " << cv.get_ca_name() << endl;
    }else{
        cout << "Certificate NOT valid, aborting connection..." << endl;
        exit(1);
    }

    while (true) {
        // Scrittura verso server
        string msg;
        cin >> msg;
        cc.send_msg(msg.c_str());

        cc.read_msg(msg_buffer);
        printf("%s\n", msg_buffer);
    }

    return 0;
}