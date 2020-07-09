#include <limits.h>  // for INT_MAX
#include <openssl/bio.h>
#include <openssl/err.h>  // for error descriptions
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <stdio.h>   // for fopen(), etc.
#include <string.h>  // for memset()

#include <iostream>
#include <string>

using namespace std;

class CertificateVerifier {
    X509* ca_cert = NULL;
    X509* server_cert = NULL;
    X509_CRL* crl = NULL;
    X509_STORE* store = NULL;
    EVP_MD_CTX* md_ctx = NULL;
    int ret;

    int open_certificate(string certificate_file_name, X509*& cert) {
        FILE* cert_file = fopen(certificate_file_name.c_str(), "r");
        if (!cert_file) {
            cerr << "Error: cannot open file '" << certificate_file_name << "' (missing?)\n";
            return -1;
        }
        cert = PEM_read_X509(cert_file, NULL, NULL, NULL);
        fclose(cert_file);
        if (!cert) {
            cerr << "Error: PEM_read_X509 returned NULL\n";
            return -1;
        }
        return 0;
    }

   public:
    int open_ca_certificate_file(string certificate_file_name) {
        return open_certificate(certificate_file_name, ca_cert);
    }

    int open_server_certificate(string certificate_file_name) {
        return open_certificate(certificate_file_name, server_cert);
    }

    int open_crl(string crl_file_name) {
        FILE* crl_file = fopen(crl_file_name.c_str(), "r");
        if (!crl_file) {
            cerr << "Error: cannot open file '" << crl_file_name << "' (missing?)\n";
            return -1;
        }
        crl = PEM_read_X509_CRL(crl_file, NULL, NULL, NULL);
        fclose(crl_file);
        if (!crl) {
            cerr << "Error: PEM_read_X509_CRL returned NULL\n";
            return -1;
        }
        return 0;
    }

    int build_store() {
        store = X509_STORE_new();
        if (!store) {
            cerr << "Error: X509_STORE_new returned NULL\n"
                 << ERR_error_string(ERR_get_error(), NULL) << "\n";
            return -1;
        }
        ret = X509_STORE_add_cert(store, ca_cert);
        if (ret != 1) {
            cerr << "Error: X509_STORE_add_cert returned " << ret << "\n"
                 << ERR_error_string(ERR_get_error(), NULL) << "\n";
            return -1;
        }
        ret = X509_STORE_add_crl(store, crl);
        if (ret != 1) {
            cerr << "Error: X509_STORE_add_crl returned " << ret << "\n"
                 << ERR_error_string(ERR_get_error(), NULL) << "\n";
            return -1;
        }
        ret = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
        if (ret != 1) {
            cerr << "Error: X509_STORE_set_flags returned " << ret << "\n"
                 << ERR_error_string(ERR_get_error(), NULL) << "\n";
            return -1;
        }
        return 0;
    }

    int verify_server_certificate() {
        // 1 se il certificato è valido, 0 non valido, -1 errore
        // Ricordare di chiamare free_all() al termine
        X509_STORE_CTX* certvfy_ctx = X509_STORE_CTX_new();
        if (!certvfy_ctx) {
            cerr << "Error: X509_STORE_CTX_new returned NULL\n"
                 << ERR_error_string(ERR_get_error(), NULL) << "\n";
            return -1;
        }
        ret = X509_STORE_CTX_init(certvfy_ctx, store, server_cert, NULL);
        if (ret != 1) {
            cerr << "Error: X509_STORE_CTX_init returned " << ret << "\n"
                 << ERR_error_string(ERR_get_error(), NULL) << "\n";
            return -1;
        }
        ret = X509_verify_cert(certvfy_ctx);
        if (ret != 1) {
            cerr << "Error: X509_verify_cert returned " << ret << "\n"
                 << ERR_error_string(ERR_get_error(), NULL) << "\n";
            return -1;
        }
        X509_STORE_CTX_free(certvfy_ctx);
        return 1;
    }

    int verify_server_certificate(string server_cert_file_name, string ca_cert_file_name, string crl_file_name) {
        // 1 se il certificato è valido, 0 non valido, -1 errore
        // Ricordare di chiamare free_all() al termine
        if (open_ca_certificate_file(ca_cert_file_name) != 0) {
            return -1;
        }
        if (open_crl(crl_file_name) != 0) {
            return -1;
        }
        if (build_store()) {
            return -1;
        }
        if (open_server_certificate(server_cert_file_name) != 0) {
            return -1;
        }
        return verify_server_certificate();
    }

    const char* get_server_name() {
        // free() it after reading
        return X509_NAME_oneline(X509_get_subject_name(server_cert), NULL, 0);
    }

    const char* get_ca_name() {
        // free() it after reading
        return X509_NAME_oneline(X509_get_issuer_name(server_cert), NULL, 0);
    }

    int verify_signed_file(const unsigned char* sgnt_buf, unsigned int sgnt_size, const unsigned char* clear_text_buffer, unsigned clear_size, string server_cert_file_name) {
        // It is 0 if invalid signature, -1 if some other error, 1 if success.
        // Inserire NULL al path del certificato se già caricato in precedenza

        // Apre il certificato se non presente
        if (server_cert == NULL) {
            if (!open_server_certificate(server_cert_file_name) == 0) {
                return -1;
            }
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
        ret = EVP_VerifyUpdate(md_ctx, clear_text_buffer, clear_size);
        if (ret == 0) {
            cerr << "Error: EVP_VerifyUpdate returned " << ret << "\n";
            return -1;
        }
        ret = EVP_VerifyFinal(md_ctx, sgnt_buf, sgnt_size, X509_get_pubkey(server_cert));
        if (ret == -1) {  // it is 0 if invalid signature, -1 if some other error, 1 if success.
            cerr << "Error: EVP_VerifyFinal returned " << ret << " (invalid signature?)\n";
            return -1;
        } else if (ret == 0) {
            cerr << "Error: Invalid signature!\n";
            return 0;
        }
        EVP_MD_CTX_free(md_ctx);
        return 1;
    }

    void free_all() {
        free_server_cert();
        // comprende ca_cert e crl
        free_store();
    }
    void free_store() {
        X509_STORE_free(store);
    }
    void free_server_cert() {
        X509_free(server_cert);
    }
    void free_ca_cert() {
        X509_free(ca_cert);
    }
    void free_CRL() {
        X509_CRL_free(crl);
    }

    ~CertificateVerifier() {
        // Il distruttore dealloca tutto in automatico
        free_all();
    }
};