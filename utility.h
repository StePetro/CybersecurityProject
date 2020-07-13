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

#include "Authenticated_Encription/gcm.h"
#include "Key_Exchange/DHKE.h"
#include "Nonce/nonce_operations.h"
#include "Signature/signer.h"

using namespace std;

#define TRUE 1
#define FALSE 0
#define PORT 8080
#define MSG_MAX_LEN 4096
#define MAX_CLIENTS 30
#define MAX_PENDING_CONNECTIONS 3
#define CERTIFICATE_PATH "PEM/server_certificate.pem"
#define PRKEY_PATH "PEM/server_private_key.pem"

int send_encrypted(unsigned char *plaintext, unsigned int plaintext_len,
                   unsigned char *aad, int aad_len,
                   unsigned char *key,
                   unsigned char *nonce,
                   int socket_id) {
    // invia plaintext criptato con gcm nel socket socket_id
    // Invia il messaggio

    unsigned char *msg_buffer;
    unsigned int msg_len;

    nonce_add_one(nonce);
    if (gcm_encrypt((unsigned char *)plaintext, plaintext_len, nonce, NONCE_SIZE, key, msg_buffer, msg_len) != 0) {
        cerr << "Error in encrypting the message" << endl;
        string message = "ERR";
        if (send(socket_id, message.c_str(), message.length(), 0) != message.length()) {
            cerr << "Error in sending the message" << endl;
        }
        return -1;
    }
    if (send(socket_id, msg_buffer, msg_len, 0) != msg_len) {
        cerr << "Error in sending the message" << endl;
    }
    return 0;
}

void close_socket_logged(int socket_id, int *client_socket, Json::Value users, Json::Value logged_users, unsigned char **session_key_list, unsigned char **nonce_list, int i) {
    close(socket_id);
    client_socket[i] = 0;
    //Toglie l'utente disconnesso dalla lista
    users[logged_users[i].asString()]["IP"] = {};
    users[logged_users[i].asString()]["PORT"] = {};
    users[logged_users[i].asString()]["READY"] = {};
    users[logged_users[i].asString()]["i"] = {};
    logged_users[i] = {};
#pragma optimize("", off)
    memset(nonce_list[i], 0, NONCE_SIZE);
    memset(session_key_list[i], 0, SESSION_KEY_SIZE);
#pragma optimize("", on)
}

int read_encrypted(char *buffer, unsigned int bytes_read, unsigned char *&decrypted_msg, unsigned int &decrypted_msg_len, unsigned char **nonce_list, Json::Value users, unsigned char **session_key_list, int i, int socket_id, int *client_socket, Json::Value socket_slots) {
    // setta decrypted_msg e decrypted_msg_len, ritorna 0 se ha successo, -1 altrimenti

    nonce_add_one(nonce_list[i]);
    if (memcmp(buffer + IV_LEN, nonce_list[i], NONCE_SIZE) != 0) {
        cerr << "Wrong nonce" << endl;
        close_socket_logged(socket_id, client_socket, users, socket_slots, session_key_list, nonce_list, i);
        return -1;
    }
    if (gcm_decrypt((unsigned char *)buffer, bytes_read, NONCE_SIZE, session_key_list[i], decrypted_msg, decrypted_msg_len) != 0) {
        cerr << "Decryption failed" << endl;
        close_socket_logged(socket_id, client_socket, users, socket_slots, session_key_list, nonce_list, i);
        return -1;
    }

    cout << "Messaggio decifrato: " << decrypted_msg << " lunghezza: " << decrypted_msg_len << endl;
    return 0;
}