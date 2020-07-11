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

#include <fstream>
#include <iostream>

#include "Key_Exchange/DHKE.h"
#include "Nonce/nonce_operations.h"
#include "Signature/signer.h"

int main(int argc, char *argv[]) {
    
    RAND_poll();
    unsigned char nonce[NONCE_SIZE] ;
    RAND_bytes((unsigned char *)&nonce[0], NONCE_SIZE);
    BIO_dump_fp(stdout, (const char *)nonce, NONCE_SIZE);

    Json::Value users;

    ifstream users_file("users.json", ifstream::binary);
    users_file >> users;

    cout << nonce << endl;


    users["Alice"]["nonce_pointer"] = nonce;

    cout << users << endl;

   /* unsigned char *Pointer = users["Alice"]["nonce_pointer"];
    BIO_dump_fp(stdout, (const char *)Pointer, NONCE_SIZE);*/

}