#include <openssl/bio.h>
#include "Socket/server.h"

int main(int argc, char const *argv[]){

    unsigned char msg_buffer[MSG_MAX_LEN] = {0};

    ServerConnection sc;
    sc.initialization();

    sc.read_msg(msg_buffer);
    printf("%s\n", msg_buffer);
    BIO_dump_fp (stdout, (const char *)msg_buffer, MSG_MAX_LEN);

    sc.read_msg(msg_buffer);
    printf("%s\n", msg_buffer);
    BIO_dump_fp (stdout, (const char *)msg_buffer, MSG_MAX_LEN);

    sc.read_msg(msg_buffer);
    printf("%s\n", msg_buffer);
    BIO_dump_fp (stdout, (const char *)msg_buffer, MSG_MAX_LEN);

    sc.read_msg(msg_buffer);
    printf("%s\n", msg_buffer);
    BIO_dump_fp (stdout, (const char *)msg_buffer, MSG_MAX_LEN);

    sc.read_msg(msg_buffer);
    printf("%s\n", msg_buffer);
    BIO_dump_fp (stdout, (const char *)msg_buffer, MSG_MAX_LEN);

    sc.send_reply("Ricevuti");

    return 0;
    
}