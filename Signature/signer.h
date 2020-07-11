#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>  // for fopen(), etc.

#include <iostream>
#include <limits>  // for INT_MAX
#include <string>

using namespace std;

int sign(string prvkey_file_name, unsigned char* clear_buf, unsigned int clear_size, unsigned char*& sgnt_buf, unsigned int& sgnt_size) {
    // Restituisce 0 se ha successo, -1 altrimenti
    // ATTENZIONE: ricordarsi di deallocare sgnt_buf con "delete[]" 
    
    int ret;  // used for return values

    // load my private key:
    FILE* prvkey_file = fopen(prvkey_file_name.c_str(), "r");
    if (!prvkey_file) {
        cerr << "Error: cannot open file '" << prvkey_file_name << "' (missing?)\n";
        return -1;
    }
    EVP_PKEY* prvkey = PEM_read_PrivateKey(prvkey_file, NULL, NULL, NULL);
    fclose(prvkey_file);
    if (!prvkey) {
        cerr << "Error: PEM_read_PrivateKey returned NULL\n";
        return -1;
    }

    // declare some useful variables:
    const EVP_MD* md = EVP_sha256();

    // create the signature context:
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        cerr << "Error: EVP_MD_CTX_new returned NULL\n";
        return -1;
    }

    // allocate buffer for signature:
    sgnt_buf = new unsigned char[EVP_PKEY_size(prvkey)];

    // sign the plaintext:
    // (perform a single update on the whole plaintext,
    // assuming that the plaintext is not huge)
    ret = EVP_SignInit(md_ctx, md);
    if (ret == 0) {
        cerr << "Error: EVP_SignInit returned " << ret << "\n";
        return -1;
    }
    ret = EVP_SignUpdate(md_ctx, clear_buf, clear_size);
    if (ret == 0) {
        cerr << "Error: EVP_SignUpdate returned " << ret << "\n";
        return -1;
    }
    ret = EVP_SignFinal(md_ctx, sgnt_buf, &sgnt_size, prvkey);
    if (ret == 0) {
        cerr << "Error: EVP_SignFinal returned " << ret << "\n";
        return -1;
    }

    //cout << sgnt_size << endl;

    // delete the digest and the private key from memory:
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(prvkey);

    return 0;
}

int verify_sign(string pubkey_file_name, unsigned char* clear_buf, unsigned int clear_size, unsigned char* sgnt_buf, unsigned int sgnt_size) {
    int ret;  // used for return values

    // load the peer's public key:
    FILE* pubkey_file = fopen(pubkey_file_name.c_str(), "r");
    if (!pubkey_file) {
        cerr << "Error: cannot open file '" << pubkey_file_name << "' (missing?)\n";
        return -1;
    }
    EVP_PKEY* pubkey = PEM_read_PUBKEY(pubkey_file, NULL, NULL, NULL);
    fclose(pubkey_file);
    if (!pubkey) {
        cerr << "Error: PEM_read_PUBKEY returned NULL\n";
        return -1;
    }

    // declare some useful variables:
    const EVP_MD* md = EVP_sha256();

    // create the signature context:
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        cerr << "Error: EVP_MD_CTX_new returned NULL\n";
        return -1;
    }

    // verify the plaintext:
    // (perform a single update on the whole plaintext,
    // assuming that the plaintext is not huge)
    ret = EVP_VerifyInit(md_ctx, md);
    if (ret == 0) {
        cerr << "Error: EVP_VerifyInit returned " << ret << "\n";
        return -1;
    }
    ret = EVP_VerifyUpdate(md_ctx, clear_buf, clear_size);
    if (ret == 0) {
        cerr << "Error: EVP_VerifyUpdate returned " << ret << "\n";
        return -1;
    }
    ret = EVP_VerifyFinal(md_ctx, sgnt_buf, sgnt_size, pubkey);
    if (ret != 1) {  // it is 0 if invalid signature, -1 if some other error, 1 if success.
        cerr << "Error: EVP_VerifyFinal returned " << ret << " (invalid signature?)\n";
        return -1;
    }

    // deallocate buffers:
    EVP_PKEY_free(pubkey);
    EVP_MD_CTX_free(md_ctx);

    return 0;
}