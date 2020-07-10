#include <arpa/inet.h>  //close
#include <errno.h>
#include <jsoncpp/json/json.h>
#include <netinet/in.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>  //strlen
#include <sys/socket.h>
#include <sys/time.h>  //FD_SET, FD_ISSET, FD_ZERO macros
#include <sys/types.h>
#include <unistd.h>  //close
#include "Key_Exchange/DHKE.h"

#include <fstream>
#include <iostream>

#include "Signature/signer.h"

using namespace std;

main(int argc, char const *argv[]) {
    
    
    EVP_PKEY* keys_s = NULL;
    EVP_PKEY* keys_s_des = NULL;
    EVP_PKEY* keys_c = NULL;
    unsigned char* public_key_s = NULL;
    unsigned char* public_keys_c = NULL;
    unsigned int size_s;
    unsigned int size_c;
    unsigned char* skeyS = NULL;
    unsigned char* skeyC = NULL;

    create_ephemeral_keys(keys_s);

    create_ephemeral_keys(keys_c);

    cout << "Tutto ok" << endl;
    //derive_session_key(keys_s, public_keys_c, skeyS);
    
    //derive_session_key(keys_c, public_key_s, skeyC);

    cout << "Server dump" << endl;
    BIO_dump_fp(stdout, (const char*) keys_s, EVP_PKEY_size(keys_s));

    cout << "Client dump" << endl;
    BIO_dump_fp(stdout, (const char*) keys_c, EVP_PKEY_size(keys_c));

    serialize_pub_key(keys_s, public_key_s, size_s);

    cout << "chiave pubblica server serializzata: " << public_key_s << endl << "dimensione: " << size_s << endl;

    deserialize_pub_key(public_key_s, size_s, keys_s_des);

    cout << "struttura deserializzata: " << endl;

    BIO_dump_fp(stdout, (const char*) keys_s_des, EVP_PKEY_size(keys_s_des));

    //derive_session_key(keys_s, keys_c, skeyS);
    //derive_session_key(keys_c, keys_s, skeyC);

    EVP_PKEY_free(keys_s);
    EVP_PKEY_free(keys_c);
    EVP_PKEY_free(keys_s_des);
    //delete[] skeyS;
    //delete[] skeyC;

    delete[] public_key_s;
}