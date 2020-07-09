#include <limits.h>  // for INT_MAX
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <stdio.h>   // for fopen(), etc.
#include <string.h>  // for memset()

#include <iostream>
#include <string>

using namespace std;


class DHKE {
   public:

    // this function returns the structure EVP_PKEY with the parameters of the new session
    // it expects to be able to allocate a new structure
    int Create_params(EVP_PKEY*& params) {
        params = EVP_PKEY_new();
        if (NULL == params) {
            printf("An error has occurred while creating parameters structure\n");
            return -1;
        }

        // we get the parameters 
        DH* temp = DH_get_2048_224();
        if (1 != EVP_PKEY_set1_DH(params, temp)) {
            printf("An error has occurred while setting parameters structure\n");
            return -1;
        }

        DH_free(temp);
        return 0;
    }

    // it allocates my_dhkey with a structure containing public and private key generated
    int Create_private_key(EVP_PKEY* params, EVP_PKEY* &my_dhkey) {

        EVP_PKEY_CTX* DHctx;
        my_dhkey = EVP_PKEY_new();

        if (NULL == my_dhkey) {
            printf("An error has occurred while creating parameters structure\n");
            return -1;
        }
        /* Create context for the key generation */
        if (!(DHctx = EVP_PKEY_CTX_new(params, NULL))) {
            printf("An Error has occurred while creating the context for effemeral key generation\n");
            return -1;
        }
        
        /* Generate a new key */
        if (1 != EVP_PKEY_keygen_init(DHctx)) {
            printf("An Error has occurred while executing keygen init\n");
            return -1;
        }
        
        if (1 != EVP_PKEY_keygen(DHctx, &my_dhkey)) {
            printf("An Error has occurred while generating effemeral keys\n");
            return -1;
        }

        EVP_PKEY_CTX_free(DHctx);
        return 0;
    }

    // given the pub key of the peer and my private key it derives the session key (already hashed with SHA 256)
    int Derive_session_key(EVP_PKEY* my_dhkey, EVP_PKEY* peer_pubkey, unsigned char*& skey) {
        /*creating a context, the buffer for the shared key and an int for its length*/
        
        EVP_PKEY_CTX* derive_ctx;
        unsigned char* shared_secret;
        size_t shared_secret_len;
       
        // a context to derive the shared secret is created with my dh keys
        derive_ctx = EVP_PKEY_CTX_new(my_dhkey, NULL);
        if (!derive_ctx) {
            printf("An error in creating the context to derive the shared secret has occurred\n");
            return -1;
        }

        if (EVP_PKEY_derive_init(derive_ctx) <= 0) {
            printf("An error while initializing the context has occurred\n");
            return -1;
        }
        /*Setting the peer with its pubkey*/
        if (EVP_PKEY_derive_set_peer(derive_ctx, peer_pubkey) <= 0) {
            printf("An error while loding peer pub key has occurred\n");
            return -1;
        }
        /* Determine buffer length, by performing a derivation but writing the result nowhere */
        EVP_PKEY_derive(derive_ctx, NULL, &shared_secret_len);
        /*allocate buffer for the shared secret*/
        shared_secret = (unsigned char*)(malloc(int(shared_secret_len)));
        if (!shared_secret) {
            printf("An error while allocating space for the shared secret has occurred\n");
            return -1;
        }
        /*Perform again the derivation and store it in skey buffer*/
        if (EVP_PKEY_derive(derive_ctx, shared_secret, &shared_secret_len) <= 0) {
            printf("An error while saving the shared secret has occurred\n");
            return -1;
        }
        printf("Here it is the shared secret: \n");
        BIO_dump_fp(stdout, (const char*)shared_secret, shared_secret_len);

        EVP_MD_CTX* Hctx;
        Hctx = EVP_MD_CTX_new();
        unsigned int skeylen;

        //allocate memory for digest
        skey = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));
        //init, Update (only once) and finalize digest
        EVP_DigestInit(Hctx, EVP_sha256());
        EVP_DigestUpdate(Hctx, (unsigned char*)shared_secret, shared_secret_len);
        EVP_DigestFinal(Hctx, skey, &skeylen);
        //Print digest to screen in hexadecimal
        
        int n;
        printf("Digest is:\n");
        for (n = 0; n<EVP_MD_size(EVP_sha256()); n++)
            printf("%02x", (unsigned char)skey[n]);
        printf("\n");

        //FREE EVERYTHING INVOLVED WITH THE EXCHANGE
        // Erase completely the shared secret
        #pragma optimize("", off)
        memset(shared_secret, 0, shared_secret_len);
        #pragma optimize("", on)
        free(shared_secret);

        EVP_PKEY_CTX_free(derive_ctx);
        EVP_MD_CTX_free(Hctx);
        return 0;
    }
};
