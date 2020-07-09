#include <openssl/bio.h>
#include <openssl/rand.h>

#include <iostream>

#include "Certificate/certificate_verifier.h"
#include "Signature/signer.h"
#include "Socket/peer_client.h"
#include "Socket/peer_server.h"

main(int argc, char const *argv[]) {
    Signer s;

    string clear = "ciao";
    unsigned char* firma;
    unsigned int len;

    s.sign("PEM/server_private_key.pem",(unsigned char*)clear.c_str(),clear.length(), firma, len );

    CertificateVerifier cv;

    cout << cv.verify_signed_file(firma,len,(unsigned char*)clear.c_str(),clear.length(),"PEM/ServerToClientCert.pem") << endl;
    return 0;
}