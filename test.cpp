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
    
    EVP_PKEY* params = NULL;
    EVP_PKEY* keys_s = NULL;
    EVP_PKEY* keys_c = NULL;
    EVP_PKEY* public_key_s = NULL;
    EVP_PKEY* public_keys_c = NULL;
    unsigned char* skeyS = NULL;
    unsigned char* skeyC = NULL;
    size_t len_s;

    DHKE dhS;
    DHKE dhC;

    dhS.Create_params(params);

    dhS.Create_private_key(params, keys_s, public_key_s);

    
    dhC.Create_private_key(params, keys_c, public_keys_c);

    
    dhS.Derive_session_key(keys_s, public_keys_c, skeyS);
    
    dhC.Derive_session_key(keys_c, public_key_s, skeyC);



    //free(buf);

    EVP_PKEY_free(params);
  
    EVP_PKEY_free(public_key_s);
  
    EVP_PKEY_free(public_keys_c);

    EVP_PKEY_free(keys_s);

    EVP_PKEY_free(keys_c);

    delete[] skeyS;
  
    delete[] skeyC;

}