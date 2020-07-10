#include <openssl/bio.h>
#include <openssl/rand.h>

#include <bitset>
#include <fstream>
#include <iostream>

#include "Signature/signer.h"

using namespace std;

#define NONCE_SIZE 8

std::bitset<NONCE_SIZE*8> bitwise_nunce_add_one(std::bitset<NONCE_SIZE*8> a) {
    std::bitset<NONCE_SIZE*8> const b("1");
    std::bitset<NONCE_SIZE*8> const m("1");  //carry
    std::bitset<NONCE_SIZE*8> result;
    for (auto i = 0; i < result.size(); ++i) {
        std::bitset<NONCE_SIZE*8> const diff(((a >> i) & m).to_ullong() + ((b >> i) & m).to_ullong() + (result >> i).to_ullong());
        result ^= (diff ^ (result >> i)) << i;
    }
    return result;
}

std::bitset<NONCE_SIZE*8> buffer_to_nonce(unsigned char *buffer) {
    std::bitset<NONCE_SIZE*8> b;

    for (int i = 0; i < NONCE_SIZE; ++i) {
        unsigned char cur = buffer[i];
        int offset = i * 8;

        for (int bit = 0; bit < 8; ++bit) {
            b[offset] = cur & 1;
            ++offset;   // Move to next bit in b
            cur >>= 1;  // Move to next bit in array
        }
    }

    return b;
}

main(int argc, char const *argv[]) {
   /* RAND_poll();
    unsigned char *nonce = new unsigned char[NONCE_SIZE];
    RAND_bytes((unsigned char *)&nonce[NONCE_SIZE], NONCE_SIZE);
    std::bitset<NONCE_SIZE*8> num = buffer_to_nonce(nonce);

    cout << num << endl;
    for (int i; i < 100; i++) {
        num = bitwise_nunce_add_one(num);
        cout << num << endl;
    }*/
    RAND_poll();
    unsigned char *nonce = new unsigned char[NONCE_SIZE];
    RAND_bytes((unsigned char *)&nonce[NONCE_SIZE], NONCE_SIZE);
    uint64_t* p_num =(uint64_t*) nonce;
    uint64_t num = *p_num;
    cout << num << endl;
    for (int i=0; i < 100; i++) {
        num++;
        cout << num << endl;
    }
}