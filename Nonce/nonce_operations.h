#include <openssl/rand.h>

#include <bitset>

#define NONCE_SIZE 32

std::bitset<NONCE_SIZE * 8> bitwise_add_one(std::bitset<NONCE_SIZE * 8> a) {
    // Somma 1 al bitset
    std::bitset<NONCE_SIZE * 8> const b("1");
    std::bitset<NONCE_SIZE * 8> const m("1");  //carry
    std::bitset<NONCE_SIZE * 8> result;
    for (auto i = 0; i < result.size(); ++i) {
        std::bitset<NONCE_SIZE * 8> const diff(((a >> i) & m).to_ullong() + ((b >> i) & m).to_ullong() + (result >> i).to_ullong());
        result ^= (diff ^ (result >> i)) << i;
    }
    return result;
}

std::bitset<NONCE_SIZE * 8> buffer_to_bitset(unsigned char *buffer) {
    // Da buffer di unsigned char a bitset
    std::bitset<NONCE_SIZE * 8> b;
    for (int i = 0; i < NONCE_SIZE; ++i) {
        unsigned char cur = buffer[i];
        int offset = i * 8;
        for (int bit = 0; bit < 8; ++bit) {
            b[offset] = cur & 1;
            ++offset;
            cur >>= 1;
        }
    }
    return b;
}

void bitset_to_buffer(std::bitset<NONCE_SIZE * 8> bits, unsigned char *buf) {
    // Da bitset a buffer di unsigned char
    // Il buffer deve essere già allocato
    size_t offset = NONCE_SIZE - 1;
    for (size_t j = 0; j < NONCE_SIZE * 8 / CHAR_BIT; ++j) {
        char next = 0;
        for (size_t i = 0; i < CHAR_BIT; ++i) {
            size_t index = NONCE_SIZE * 8 - (CHAR_BIT * j) - i - 1;
            size_t pos = CHAR_BIT - i - 1;
            if (bits[index])
                next |= (1 << pos);
        }
        buf[offset] = next;
        offset--;
    }
}

void nonce_add_one(unsigned char *buf) {
    // Incrementa di 1 il nonce dentro al buffer
    std::bitset<NONCE_SIZE * 8> num = buffer_to_bitset(buf);
    num = bitwise_add_one(num);
    bitset_to_buffer(num, buf);
}