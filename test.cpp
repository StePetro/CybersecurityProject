#include <openssl/bio.h>

#include <iostream>

#include "Encryption/asymmetric_encrypter.h"
#include "Certificate/certificate_verifier.h"

using namespace std;

main(int argc, char const *argv[]) {
    /*AsymmetricEncrypter ae;
    unsigned char *enc_msg;
    size_t enc_msg_size;
    ae.encrypt("PEM/alice_public_key.pem", "Messaggio criptato", enc_msg, enc_msg_size);
    string message = ae.decrypt("PEM/alice_private_key.pem", enc_msg, enc_msg_size);
    BIO_dump_fp(stdout, (const char *)message.c_str(), message.length());*/
    
    {
        CertificateVerifier cv;
    }

    cout << "que" << endl;



    return 0;
}