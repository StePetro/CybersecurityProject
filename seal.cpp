#include <iostream> 
#include <string>
#include <stdio.h> // for fopen(), etc.
#include <limits.h> // for INT_MAX
#include <string.h> // for memset()
#include <openssl/evp.h>
#include <openssl/pem.h>

using namespace std;

class AsymmetricEncryption {       
    int encrypt(string pubkey_file_name, string messageToEncrypt) {
        int ret; // used for return values

        // load the peer's public key:
        FILE* pubkey_file = fopen(pubkey_file_name.c_str(), "r");
        if (!pubkey_file) { cerr << "Error: cannot open file '" << pubkey_file_name << "' (missing?)\n"; exit(1); }
        EVP_PKEY* pubkey = PEM_read_PUBKEY(pubkey_file, NULL, NULL, NULL);
        fclose(pubkey_file);
        if (!pubkey) { cerr << "Error: PEM_read_PUBKEY returned NULL\n"; exit(1); }

        // get the message size: 
        long int clear_size = sizeof messageToEncrypt;

        // read the plaintext from "messageToEncrypt":
        unsigned char* clear_buf = (unsigned char*)malloc(clear_size);
        if (!clear_buf) { cerr << "Error: malloc returned NULL (message too big?)\n"; exit(1); }
        *clear_buf = messageToEncrypt;

        // declare some useful variables:
        const EVP_CIPHER* cipher = EVP_aes_128_cbc();
        int encrypted_key_len = EVP_PKEY_size(pubkey);
        int iv_len = EVP_CIPHER_iv_length(cipher);
        int block_size = EVP_CIPHER_block_size(cipher);

        // create the envelope context
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) { cerr << "Error: EVP_CIPHER_CTX_new returned NULL\n"; exit(1); }

        // allocate buffers for encrypted key and IV:
        unsigned char* encrypted_key = (unsigned char*)malloc(encrypted_key_len);
        unsigned char* iv = (unsigned char*)malloc(EVP_CIPHER_iv_length(cipher));
        if (!encrypted_key || !iv) { cerr << "Error: malloc returned NULL (encrypted key too big?)\n"; exit(1); }

        // check for possible integer overflow in (clear_size + block_size)
        // (possible if the plaintext is too big, assume non-negative clear_size and block_size):
        if (clear_size > INT_MAX - block_size) { cerr << "Error: integer overflow (file too big?)\n"; exit(1); }

        // allocate a buffer for the ciphertext:
        int enc_buffer_size = clear_size + block_size;
        unsigned char* cphr_buf = (unsigned char*)malloc(enc_buffer_size);
        if (!cphr_buf) { cerr << "Error: malloc returned NULL (file too big?)\n"; exit(1); }

        // encrypt the plaintext:
        // (perform a single update on the whole plaintext, 
        // assuming that the plaintext is not huge)
        ret = EVP_SealInit(ctx, cipher, &encrypted_key, &encrypted_key_len, iv, &pubkey, 1);
        if (ret <= 0) { // it is "<=0" to catch the (undocumented) case of -1 return value, when the operation is not supported (e.g. attempt to use digital envelope with Elliptic Curve keys)
            cerr << "Error: EVP_SealInit returned " << ret << "\n";
            exit(1);
        }
        int nc = 0; // bytes encrypted at each chunk
        int nctot = 0; // total encrypted bytes
        ret = EVP_SealUpdate(ctx, cphr_buf, &nc, clear_buf, clear_size);
        if (ret == 0) { cerr << "Error: EVP_SealUpdate returned " << ret << "\n"; exit(1); }
        nctot += nc;
        ret = EVP_SealFinal(ctx, cphr_buf + nctot, &nc);
        if (ret == 0) { cerr << "Error: EVP_SealFinal returned " << ret << "\n"; exit(1); }
        nctot += nc;
        int cphr_size = nctot;

        // delete the symmetric key and the plaintext from memory:
        EVP_CIPHER_CTX_free(ctx);
        #pragma optimize("", off)
        memset(clear_buf, 0, clear_size);
        #pragma optimize("", on)
        free(clear_buf);

        // write the encrypted key, the IV, and the ciphertext into a '.enc' file:
        string cphr_file_name = messageToEncrypt + ".enc";
        FILE* cphr_file = fopen(cphr_file_name.c_str(), "wb");
        if (!cphr_file) { cerr << "Error: cannot open file '" << cphr_file_name << "' (no permissions?)\n"; exit(1); }
        ret = fwrite(encrypted_key, 1, encrypted_key_len, cphr_file);
        if (ret < encrypted_key_len) { cerr << "Error while writing the file '" << cphr_file_name << "'\n"; exit(1); }
        ret = fwrite(iv, 1, EVP_CIPHER_iv_length(cipher), cphr_file);
        if (ret < EVP_CIPHER_iv_length(cipher)) { cerr << "Error while writing the file '" << cphr_file_name << "'\n"; exit(1); }
        ret = fwrite(cphr_buf, 1, cphr_size, cphr_file);
        if (ret < cphr_size) { cerr << "Error while writing the file '" << cphr_file_name << "'\n"; exit(1); }
        fclose(cphr_file);

        cout << "File '" << messageToEncrypt << "' encrypted into file '" << cphr_file_name << "'\n";

        // deallocate buffers:
        free(cphr_buf);
        free(encrypted_key);
        free(iv);
        EVP_PKEY_free(pubkey);

        return 0;
    }
};

int main() {
    AsymmetricEncryption ae;
    ae.encrypt(, "Messaggio criptato");
    return 0;
}
