#include <limits>  // for INT_MAX
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include <iostream>
#include <string>

#define TAG_LEN 16
#define IV_LEN 12

using namespace std;

int gcm_encrypt(unsigned char *plaintext, unsigned int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *&ciphertext,
                unsigned int &ciphertext_len,
                unsigned char *&tag) {
    // Restituisce 0 se ha successo e setta tag, ciphertext e la sua lunghezza, -1 altrimenti
    // ATTENZIONE: ricordare di fare la "delete []" per ciphertext

    EVP_CIPHER_CTX *ctx;
    int len;
    ciphertext_len;
    // Alloca spazio per il cyphertext
    ciphertext = new unsigned char[plaintext_len];
    tag = new unsigned char[TAG_LEN];
    // Create and initialise the context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        cerr << "An error occourred.\n" << endl;
        return -1;
    }
    // Initialise the encryption operation.
    if (1 != EVP_EncryptInit(ctx, EVP_aes_256_gcm(), key, iv)) {
        cerr << "An error occourred.\n" << endl;
        return -1;
    }

    //Provide any AAD data. This can be called zero or more times as required
    if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) {
        cerr << "An error occourred.\n" << endl;
        return -1;
    }

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        cerr << "An error occourred.\n" << endl;
        return -1;
    }
    ciphertext_len = len;
    //Finalize Encryption
    if (1 != EVP_EncryptFinal(ctx, ciphertext + len, &len)) {
        cerr << "An error occourred.\n" << endl;
        return -1;
    }
    ciphertext_len += len;
    /* Get the tag */
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_LEN, tag)) {
        cerr << "An error occourred.\n" << endl;
        return -1;
    }
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    return 0;
}

int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, unsigned int aad_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *&plaintext,
                unsigned int &plaintext_len) {
    // Restituisce 0 e setta plaintex e plaintext_len al successo, -1 altrimenti
    // ATTENZIONE: ricordare di fare la "delete []" per plaintext

    EVP_CIPHER_CTX *ctx;
    int len;
    int ret;
    plaintext = new unsigned char[plaintext_len];
    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        cerr << "An error occourred.\n" << endl;
        return -1;
    }
    if (!EVP_DecryptInit(ctx, EVP_aes_256_gcm(), key, iv)) {
        cerr << "An error occourred.\n" << endl;
        return -1;
    }
    //Provide any AAD data.
    if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) {
        cerr << "An error occourred.\n" << endl;
        return -1;
    }
    //Provide the message to be decrypted, and obtain the plaintext output.
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        cerr << "An error occourred.\n" << endl;
        return -1;
    }
    plaintext_len = len;
    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TAG_LEN, tag)) {
        cerr << "An error occourred.\n" << endl;
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
        plaintext_len;
        return 0;
    } else {
        /* Verify failed */
        return -1;
    }
}

/*
int main(void) {
    unsigned char msg[] = "Short message";
    //create key
    unsigned char key_gcm[] = "123456789012345dvsrfvfdvf6";
    unsigned char iv_gcm[] = "123456780912";
    unsigned char *cphr_buf;
    unsigned char *tag_buf;
    unsigned int cphr_len;
    unsigned int dec_len;
    int pt_len = sizeof(msg);
    gcm_encrypt(msg, pt_len, iv_gcm, 12, key_gcm, iv_gcm, 12, cphr_buf, cphr_len, tag_buf);
    cout << "CT:" << endl;
    BIO_dump_fp(stdout, (const char *)cphr_buf, pt_len);
    cout << "Tag:" << endl;
    BIO_dump_fp(stdout, (const char *)tag_buf, 16);
    unsigned char *dec_buf;
    gcm_decrypt(cphr_buf, pt_len, iv_gcm, 12, tag_buf, key_gcm, iv_gcm, 12, dec_buf, dec_len);
    cout << "PT:" << endl;
    BIO_dump_fp(stdout, (const char *)dec_buf, pt_len);
    return 0;
}*/
