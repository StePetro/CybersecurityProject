#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include <iostream>
#include <limits>  // for INT_MAX
#include <string>
#include <stdio.h>
#include <string.h>

#define TAG_LEN 16
#define IV_LEN 12

using namespace std;

int gcm_encrypt(unsigned char *plaintext, unsigned int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *&msg_buffer,
                unsigned int& msg_len) {
    // Restituisce 0 se ha successo e setta tag, ciphertext e la sua lunghezza, -1 altrimenti
    // ATTENZIONE: ricordare di fare la "delete []" per ciphertext
    // msg_buffer = (iv || aad || cyphertext || tag)

    // IV casuale
    RAND_poll();
    unsigned char *iv = new unsigned char[IV_LEN];
    RAND_bytes((unsigned char *)&iv[0], IV_LEN);

    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    // Alloca spazio per il cyphertext
    unsigned char *ciphertext = new unsigned char[plaintext_len];
    unsigned char *tag = new unsigned char[TAG_LEN];
    // Create and initialise the context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        cerr << "An error occourred.\n"
             << endl;
        return -1;
    }
    // Initialise the encryption operation.
    if (1 != EVP_EncryptInit(ctx, EVP_aes_256_gcm(), key, iv)) {
        cerr << "An error occourred.\n"
             << endl;
        return -1;
    }

    // (IV || resto aad)
    unsigned char *aad_total = new unsigned char[IV_LEN + aad_len];
    memcpy(aad_total, iv, IV_LEN);
    memcpy(aad_total + IV_LEN, aad, aad_len);

    //Provide any AAD data. This can be called zero or more times as required
    if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad_total, aad_len)) {
        cerr << "An error occourred.\n"
             << endl;
        return -1;
    }

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        cerr << "An error occourred.\n"
             << endl;
        return -1;
    }
    ciphertext_len = len;
    //Finalize Encryption
    if (1 != EVP_EncryptFinal(ctx, ciphertext + len, &len)) {
        cerr << "An error occourred.\n"
             << endl;
        return -1;
    }
    ciphertext_len += len;
    /* Get the tag */
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_LEN, tag)) {
        cerr << "An error occourred.\n"
             << endl;
        return -1;
    }

    // msg = (iv || aad || cyphertext || tag)
    msg_buffer = new unsigned char[IV_LEN + aad_len + ciphertext_len + TAG_LEN];
    memcpy(msg_buffer, aad_total, IV_LEN + aad_len);
    memcpy(msg_buffer + IV_LEN + aad_len, ciphertext, ciphertext_len);
    memcpy(msg_buffer + IV_LEN + aad_len + ciphertext_len, tag, TAG_LEN);

    msg_len = IV_LEN + aad_len + ciphertext_len + TAG_LEN;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    delete[] ciphertext;
    delete[] tag;
    delete[] aad_total;
    return 0;
}

int gcm_decrypt(unsigned char *msg_buffer, unsigned int msg_len,
                int aad_len,
                unsigned char *key,
                unsigned char *&plaintext) {
    // Restituisce 0 e setta plaintex e plaintext_len al successo, -1 altrimenti
    // ATTENZIONE: ricordare di fare la "delete []" per plaintext
    // Plaintext 

    plaintext = new unsigned char[msg_len - aad_len -IV_LEN -TAG_LEN];

    EVP_CIPHER_CTX *ctx;
    int len;
    int ret;
    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        cerr << "An error occourred.\n"
             << endl;
        return -1;
    }
    // msg_buffer = (iv || aad || cyphertext || tag)
    if (!EVP_DecryptInit(ctx, EVP_aes_256_gcm(), key, msg_buffer)) {
        cerr << "An error occourred.\n"
             << endl;
        return -1;
    }
    //Provide any AAD data.
    // msg_buffer = (iv || aad || cyphertext || tag)
    if (!EVP_DecryptUpdate(ctx, NULL, &len, msg_buffer, aad_len + IV_LEN)) {
        cerr << "An error occourred.\n"
             << endl;
        return -1;
    }
    //Provide the message to be decrypted, and obtain the plaintext output.
    // msg_buffer = (iv || aad || cyphertext || tag)
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, msg_buffer + aad_len + IV_LEN, msg_len - TAG_LEN - IV_LEN - aad_len)) {
        cerr << "An error occourred.\n"
             << endl;
        return -1;
    }
    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    // msg_buffer = (iv || aad || cyphertext || tag)
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TAG_LEN,msg_buffer + msg_len -TAG_LEN )) {
        cerr << "An error occourred.\n"
             << endl;
        return -1;
    }
    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal(ctx, plaintext + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_cleanup(ctx);

    if (ret > 0) {
        /* Success */
        return 0;
    } else {
        /* Verify failed */
        return -1;
    }
}

/*
int main(void) {
    unsigned char msg[] = "Short message ddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd 11111111111111111111111111111111111111111111111111111111  0000000000  ijnoooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooijnijnijnijniiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiidskfvwrfkndvorwfndvwfvmlllllllllllllllllllllllllllllllllllllllllllllllllllasfcewrkeckkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkwerfvjrewjfdvnrfkvnm,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,wevmrwfkvmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmfekomweomvoermkvokervffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff@";
    //create key
    unsigned char key_gcm[] = "123456789012345dvsrfvfdvf6";
    unsigned char iv_gcm[] = "123456780912";
    unsigned char *cphr_buf;
    unsigned char *tag_buf;
    unsigned int cphr_len;
    unsigned int dec_len;
    unsigned char* risposta;
    unsigned int risposta_len;
    unsigned int pt_len = sizeof(msg);

    // IV casuale
    RAND_poll();
    unsigned char *nonce = new unsigned char[32];
    RAND_bytes((unsigned char *)&nonce[0], 32);

    gcm_encrypt(msg, pt_len, nonce,32,key_gcm,risposta,risposta_len);
    cout << "MSG:";
    cout << risposta_len << endl;
    BIO_dump_fp(stdout, (const char *)risposta, risposta_len);
    unsigned char *dec_buf;
    gcm_decrypt(risposta,risposta_len,32,key_gcm,dec_buf);
    cout << "PT:" << endl;
    BIO_dump_fp(stdout, (const char *)dec_buf, pt_len);
    return 0;
}

*/
