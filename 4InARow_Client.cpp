#include <openssl/bio.h>
#include "Socket/client.h"

main(int argc, char const *argv[]){
    
    unsigned char msg_buffer[MSG_MAX_LEN] = {0};

    ClientConnection cc;
    cc.initialization("172.16.1.213");
    cc.send_msg("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    cc.send_msg("Prova1");
    cc.send_msg("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    cc.send_msg("Prova2");
    cc.send_msg("-");
    cc.read_reply(msg_buffer);
    printf("%s\n", msg_buffer);
    BIO_dump_fp (stdout, (const char *)msg_buffer, MSG_MAX_LEN);

    return 0;
}