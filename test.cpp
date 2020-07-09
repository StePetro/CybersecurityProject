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

#include "Signature/signer.h"

using namespace std;

main(int argc, char const *argv[]) {
    Json::Value users;
    ifstream users_file("users.json", ifstream::binary);
    users_file >> users;
    users["Alice"]["Online"] = true;
    cout << users["Alice"]<< endl;
    return 0;
}