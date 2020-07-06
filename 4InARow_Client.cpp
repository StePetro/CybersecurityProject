#include <openssl/bio.h>
#include <iostream>

#include "Socket/peer_client.h"
#include "Socket/peer_server.h"

using namespace std;

main(int argc, char const *argv[]) {
    unsigned char msg_buffer[MSG_MAX_LEN] = {0};

    PeerClientConnection cc;
    cc.initialization("172.16.1.213", 8080);

    while (true) {

        // Lettura dal server
        cc.read_msg(msg_buffer);
        printf("%s\n", msg_buffer);
        //BIO_dump_fp (stdout, (const char *)msg_buffer, MSG_MAX_LEN);

        // Scrittura verso server
        string msg;
        cin >> msg;
        cc.send_msg(msg.c_str());

    }

    return 0;
}