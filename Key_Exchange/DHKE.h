#include <limits.h>  // for INT_MAX
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>

#include <iostream>
#include <string>

#define SESSION_KEY_SIZE 32

using namespace std;


int create_ephemeral_keys(EVP_PKEY *&my_ecdhkey) {
    // this function generates effemeral private and public key of ECDH
    // ATTENTION: my_ecdhkey gets allocated, remember to free it afterwards
    printf("Start: loading NID_X9_62_prime256v1 curve parameters\n");

    EVP_PKEY_CTX *pctx;
    EVP_PKEY* params = NULL;

    if (!(pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))) {
        cout << "An error has occurred while creating a new context for DH parameters" << endl;
        return -1;
    }
    if (!EVP_PKEY_paramgen_init(pctx)) {
        cout << "An error has occurred while initializing the context" << endl;
        return -1;
    }
    /* Use the NID_X9_62_prime256v1 named curve */
    if (!EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1)) {
        cout << "An error has occurred while setting the curve to be used" << endl;
        return -1;
    }
    /* Create the parameter object params */
    if (!EVP_PKEY_paramgen(pctx, &params)) {
        cout << "An error has occurred while generating the parameters" << endl;
        return -1;
    }

    printf("Generating ephemeral ECDH KeyPair\n");
    // Create context for the key generation, an EVP structure for the key
    EVP_PKEY_CTX *ECDHctx;

    // Create the context for the key generation 
    if (NULL == (ECDHctx = EVP_PKEY_CTX_new(params, NULL))) {
        cout << "An error has occurred while creating the context for key generation" << endl;
        return -1;
    }
    // Generate the key 
    if (!EVP_PKEY_keygen_init(ECDHctx)) {
        cout << "An error has occurred while initializing the context for key generation" << endl;
        return -1;
    }
    if (!EVP_PKEY_keygen(ECDHctx, &my_ecdhkey)) {
        cout << "An error has occurred while generating the keys" << endl;
        return -1;
    }

    EVP_PKEY_CTX_free(ECDHctx);    
    EVP_PKEY_free(params);
    EVP_PKEY_CTX_free(pctx);

    return 0;
}

int derive_session_key(EVP_PKEY *my_ecdhkey, EVP_PKEY *peer_pubkey, unsigned char *&skey) {
    // this function derives the shared secret from the keys passed and it returns the session key
    // ATTENTION: it allocates skey, while deallocating both my_ecdhkey and peer_pubkey

    printf("Deriving a shared secret\n");
    //creating a context, the buffer for the shared key and an int for its length
    unsigned char *shared_secret;
    size_t shared_secret_len;

    EVP_PKEY_CTX *derive_ctx = EVP_PKEY_CTX_new(my_ecdhkey, NULL);  
    if (NULL == derive_ctx) {
        cout << "An error has occurred while creating the context for key derivation" << endl;
        return -1;
    }
    if (EVP_PKEY_derive_init(derive_ctx) <= 0) {
        cout << "An error has occurred while initializing the context for key derivation" << endl;
        return -1;
    }
    //Setting the peer with its pubkey
    if (EVP_PKEY_derive_set_peer(derive_ctx, peer_pubkey) <= 0) {
        cout << "An error has occurred while setting the peer pubkey in the context" << endl;
        return -1;
    }
    // Determine buffer length, by performing a derivation but writing the result nowhere
    EVP_PKEY_derive(derive_ctx, NULL, &shared_secret_len);

    //allocate buffer for the shared secret
    shared_secret = new unsigned char[(int(shared_secret_len))];

    if (!shared_secret) {
        cout << "An error has occurred while allocating space for the shared key" << endl;
        return -1;
    }
    //Perform again the derivation and store it in shared secret buffer
    if (EVP_PKEY_derive(derive_ctx, shared_secret, &shared_secret_len) <= 0) {
        cout << "An error has occurred while dering the keys" << endl;
        return -1;
    }

    // hash the shared secret
    EVP_MD_CTX* Hctx;
    Hctx = EVP_MD_CTX_new();
    unsigned int skeylen;

    //allocate memory for digest
    skey = new unsigned char[EVP_MD_size(EVP_sha256())];
    //init, Update (only once) and finalize digest
    EVP_DigestInit(Hctx, EVP_sha256());
    EVP_DigestUpdate(Hctx, (unsigned char*)shared_secret, shared_secret_len);
    EVP_DigestFinal(Hctx, skey, &skeylen);
    
    //Print digest to screen in hexadecimal
    int n;
    cout << "Digest is:" << endl;
    for (n = 0; n < EVP_MD_size(EVP_sha256()); n++)
        printf("%02x", (unsigned char)skey[n]);
    cout << endl;

    //FREE EVERYTHING INVOLVED WITH THE EXCHANGE 
    EVP_PKEY_CTX_free(derive_ctx);
    EVP_MD_CTX_free(Hctx);
    EVP_PKEY_free(my_ecdhkey);
    EVP_PKEY_free(peer_pubkey);

    // Erase completely the shared secret
    #pragma optimize("", off)
    memset(shared_secret, 0, shared_secret_len);
    #pragma optimize("", on)
    delete[] shared_secret;
}

int serialize_pub_key(EVP_PKEY* ecdhkey, unsigned char*& buffer, unsigned int& size){
    // this function serializes only the public key in the buffer
    // ATTENTION: it allocates buffer, remember to deallocate it afterwards

    BIO* b = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(b, ecdhkey);
    char * serialize_buffer = NULL;
    long pubkey_size = BIO_get_mem_data(b, &serialize_buffer);
    if (pubkey_size > UINT_MAX || pubkey_size < 0){
        cout << "Problem! The size of the serialized public key lies outside a simple unsigned int" << endl;
        return -1;
    }
    size = (unsigned int) pubkey_size - 1;
    buffer = new unsigned char[size];
    memcpy(buffer, serialize_buffer, size);

    BIO_free(b);
    return 0;
}

void deserialize_pub_key(unsigned char* buffer, unsigned int size, EVP_PKEY* &pub_key){
    // this function deserializes the public key in the buffer into an EVP_PKEY
    // ATTENTION: it allocates pub_key, remember to deallocate it afterwards

    BIO* b = BIO_new(BIO_s_mem());
    BIO_write(b, buffer, size);
    pub_key = PEM_read_bio_PUBKEY(b, NULL, NULL, NULL);
    BIO_free(b);

    BIO_dump_fp(stdout, (const char*) pub_key, EVP_PKEY_size(pub_key));
}

