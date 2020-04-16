#include <iostream>
#include <string>
#include <stdlib.h>
#include <stdio.h> // for fopen(), etc.
#include <limits.h> // for INT_MAX
#include <string.h> // for memset()
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
using namespace std;

class SymmetricEncrypter {

  public:

    int encrypt(unsigned char *key, string messageToEncrypt) {
      int ret; // used for return values

      // get the message size:
      long int clear_size = messageToEncrypt.size() + 1; // + 1 for the string terminator

      // read the plaintext from "messageToEncrypt":
      unsigned char* clear_buf = (unsigned char*)malloc(clear_size);
      if (!clear_buf) { cerr << "Error: malloc returned NULL (message too big?)\n"; exit(1); }
      strcpy((char *)clear_buf,messageToEncrypt.c_str());

      // declare some useful variables:
      const EVP_CIPHER* cipher = EVP_aes_128_cbc();
      int iv_len = EVP_CIPHER_iv_length(cipher);
      int block_size = EVP_CIPHER_block_size(cipher);

      // Allocate memory for and randomly generate IV:
      unsigned char* iv = (unsigned char*)malloc(iv_len);
      // Seed OpenSSL PRNG
      RAND_poll();
      // Generate IV at random
      RAND_bytes((unsigned char*)&iv[0],iv_len);

      // check for possible integer overflow in (clear_size + block_size) --> PADDING!
      // (possible if the plaintext is too big, assume non-negative clear_size and block_size):
      if(clear_size > INT_MAX - block_size) { cerr <<"Error: integer overflow (message too big?)\n"; exit(1); }
      // allocate a buffer for the ciphertext:
      int enc_buffer_size = clear_size + block_size;
      unsigned char* cphr_buf = (unsigned char*)malloc(enc_buffer_size);
      if(!cphr_buf) { cerr << "Error: malloc returned NULL (message too big?)\n"; exit(1); }

      //Create and initialise the context with used cipher, key and iv
      EVP_CIPHER_CTX *ctx;
      ctx = EVP_CIPHER_CTX_new();
      if(!ctx){ cerr << "Error: EVP_CIPHER_CTX_new returned NULL\n"; exit(1); }
      ret = EVP_EncryptInit(ctx, cipher, key, iv);
      if(ret != 1){
         cerr <<"Error: EncryptInit Failed\n";
         exit(1);
      }
      int update_len = 0; // bytes encrypted at each chunk
      int total_len = 0; // total encrypted bytes

      // Encrypt Update: one call is enough because our file is small.
      ret = EVP_EncryptUpdate(ctx, cphr_buf, &update_len, clear_buf, clear_size);
      if(ret != 1){
         cerr <<"Error: EncryptUpdate Failed\n";
         exit(1);
      }
      total_len += update_len;

      //Encrypt Final. Finalize the encryption and adds the padding
      ret = EVP_EncryptFinal(ctx, cphr_buf + total_len, &update_len);
      if(ret != 1){
         cerr <<"Error: EncryptFinal Failed\n";
         exit(1);
      }
      total_len += update_len;
      int cphr_size = total_len;

      cout << "DEBUG| Encrypted message: "<<endl;
      BIO_dump_fp (stdout, (const char *)cphr_buf, cphr_size);

      // delete the context and the plaintext from memory:
      EVP_CIPHER_CTX_free(ctx);
      // Telling the compiler it MUST NOT optimize the following instruction.
      // With optimization the memset would be skipped, because of the next free instruction.
      #pragma optimize("", off)
      memset(clear_buf, 0, clear_size);
      #pragma optimize("", on)
      free(clear_buf);

      // write the IV and the ciphertext into a '.enc' file:
      string cphr_file_name = "encrypted_message.enc";
      FILE* cphr_file = fopen(cphr_file_name.c_str(), "wb");
      if(!cphr_file) { cerr << "Error: cannot open file '" << cphr_file_name << "' (no permissions?)\n"; exit(1); }

      ret = fwrite(iv, 1, EVP_CIPHER_iv_length(cipher), cphr_file);
      if(ret < EVP_CIPHER_iv_length(cipher)) { cerr << "Error while writing the file '" << cphr_file_name << "'\n"; exit(1); }

      ret = fwrite(cphr_buf, 1, cphr_size, cphr_file);
      if(ret < cphr_size) { cerr << "Error while writing the file '" << cphr_file_name << "'\n"; exit(1); }

      fclose(cphr_file);

      cout << "Message encrypted into file '" << cphr_file_name << "'\n";

      // deallocate buffers:
      free(cphr_buf);
      free(iv);
      return 0;
    }

    string decrypt(unsigned char * key, string cphr_file_name) {
      int ret; // used for return values

      // open the file to decrypt:
      FILE* cphr_file = fopen(cphr_file_name.c_str(), "rb");
      if(!cphr_file) { cerr << "Error: cannot open file '" << cphr_file_name << "' (file does not exist?)\n"; exit(1); }

      // get the file size:
      // (assuming no failures in fseek() and ftell())
      fseek(cphr_file, 0, SEEK_END);
      long int cphr_file_size = ftell(cphr_file);
      fseek(cphr_file, 0, SEEK_SET);

      // declare some useful variables:
      const EVP_CIPHER* cipher = EVP_aes_128_cbc();
      int iv_len = EVP_CIPHER_iv_length(cipher);

      // Allocate buffer for IV, ciphertext, plaintext
      unsigned char* iv = (unsigned char*)malloc(iv_len);
      int cphr_size = cphr_file_size - iv_len;
      unsigned char* cphr_buf = (unsigned char*)malloc(cphr_size);
      unsigned char* clear_buf = (unsigned char*)malloc(cphr_size);
      if(!iv || !cphr_buf || !clear_buf) { cerr << "Error: malloc returned NULL (file too big?)\n"; exit(1); }

      // read the IV and the ciphertext from file:
      ret = fread(iv, 1, iv_len, cphr_file);
      if(ret < iv_len) { cerr << "Error while reading file '" << cphr_file_name << "'\n"; exit(1); }
      ret = fread(cphr_buf, 1, cphr_size, cphr_file);
      if(ret < cphr_size) { cerr << "Error while reading file '" << cphr_file_name << "'\n"; exit(1); }
      fclose(cphr_file);

      //Create and initialise the context
      EVP_CIPHER_CTX *ctx;
      ctx = EVP_CIPHER_CTX_new();
      if(!ctx){ cerr << "Error: EVP_CIPHER_CTX_new returned NULL\n"; exit(1); }
      ret = EVP_DecryptInit(ctx, cipher, key, iv);
      if(ret != 1){
         cerr <<"Error: DecryptInit Failed\n";
         exit(1);
      }

      int update_len = 0; // bytes decrypted at each chunk
      int total_len = 0; // total decrypted bytes

      // Decrypt Update: one call is enough because our ciphertext is small.
      ret = EVP_DecryptUpdate(ctx, clear_buf, &update_len, cphr_buf, cphr_size);
      if(ret != 1){
         cerr <<"Error: DecryptUpdate Failed\n";
         exit(1);
      }
      total_len += update_len;

      //Decrypt Final. Finalize the Decryption and adds the padding
      ret = EVP_DecryptFinal(ctx, clear_buf + total_len, &update_len);
      if(ret != 1){
         cerr <<"Error: DecryptFinal Failed\n";
         exit(1);
      }
      total_len += update_len;
      int clear_size = total_len;

      // delete the context from memory:
      EVP_CIPHER_CTX_free(ctx);

      // convert the plaintext to string:
      string message( reinterpret_cast< char const* >(clear_buf) ) ;

      cout<<"DEBUG| Used IV:"<<endl;
      BIO_dump_fp (stdout, (const char *)iv, iv_len);

      // delete the plaintext from memory:
      // Telling the compiler it MUST NOT optimize the following instruction.
      // With optimization the memset would be skipped, because of the next free instruction.
      #pragma optimize("", off)
      memset(clear_buf, 0, clear_size);
      #pragma optimize("", on)
      free(clear_buf);

      // deallocate buffers:
      free(iv);
      free(cphr_buf);

      //return the message:
      return message;
    }

};

int main() {
    SymmetricEncrypter se;
    se.encrypt((unsigned char *)"0123456789012345", "0000000000000000000000000000000 kejbvjwevbwejbvkebrfbvfjk bla bla bla bla mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm");
    string message = se.decrypt((unsigned char *)"0123456789012345", "encrypted_message.enc");
    cout << "The decrypted message is: '"<< message << "'\n";

    return 0;
}
