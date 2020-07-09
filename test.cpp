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
#include "DH/DHKE.h"

#include <fstream>
#include <iostream>

#include "Signature/signer.h"

using namespace std;

main(int argc, char const *argv[]) {
    
    EVP_PKEY* params;
    EVP_PKEY* pub_key_s;
    EVP_PKEY* pub_key_c;
    unsigned char* skeyS;
    unsigned char* skeyC;
    size_t len_s;

    DHKE dhS;
    DHKE dhC;

    dhS.Create_params(params);

    //cout<<"Parametri creati"<< endl;

    dhS.Create_private_key(params, pub_key_s);

    EVP_PKEY_get_raw_public_key(pub_key_s, NULL, &len_s);

    unsigned char * buf = (unsigned char*)(malloc(int(len_s)));

    printf("Lunghezza chiave pubblica: %u", len_s);

    EVP_PKEY_get_raw_public_key(pub_key_s, buf, &len_s);

    //printf((const char*)buf);

    //cout<<"chiave pubblica server creata!"<<endl;

    dhC.Create_private_key(params, pub_key_c);

    //cout<<"chiave pubblica client creata!"<<endl;

    //cout<<"==================Server:"<< endl;
    dhS.Derive_session_key(pub_key_s, pub_key_c, skeyS);
    //cout<<"===================Client:"<<endl;
    dhC.Derive_session_key(pub_key_c, pub_key_s, skeyC);



    free(buf);

    EVP_PKEY_free(params);
  
    EVP_PKEY_free(pub_key_s);
  
    EVP_PKEY_free(pub_key_c);

    free(skeyS);
  
    free(skeyC);

}