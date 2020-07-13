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

#include "Socket/peer_client.h"
#include "Socket/peer_server.h"

using namespace std;

main(int argc, char const *argv[]) {
    
    
    
}