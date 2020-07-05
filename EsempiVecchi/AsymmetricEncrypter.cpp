#include <iostream>
#include <string>
#include <stdio.h> // for fopen(), etc.
#include <limits.h> // for INT_MAX
#include <string.h> // for memset()
#include <openssl/evp.h>
#include <openssl/pem.h>

using namespace std;

class AsymmetricEncrypter {

  public:

    int encrypt(string pubkey_file_name, string messageToEncrypt) {

      // c_str(): Returns a pointer to an array that contains a null-terminated sequence of characters (i.e., a C-string) representing the current value of the string object.
      //          This array includes the same sequence of characters that make up the value of the string object plus an additional terminating null-character ('\0') at the end.

      cout << "DEBUG| Message: " << messageToEncrypt.c_str() << "\n";

      int ret; // used for return values

      // load the peer's public key:
      FILE* pubkey_file = fopen(pubkey_file_name.c_str(), "r");
      if (!pubkey_file) { cerr << "Error: cannot open file '" << pubkey_file_name << "' (missing?)\n"; exit(1); }
      EVP_PKEY* pubkey = PEM_read_PUBKEY(pubkey_file, NULL, NULL, NULL);
      fclose(pubkey_file);
      if (!pubkey) { cerr << "Error: PEM_read_PUBKEY returned NULL\n"; exit(1); }

      // get the message size:
      long int clear_size = messageToEncrypt.size() + 1; // + 1 for the string terminator

      cout << "DEBUG| clear message size: " << clear_size << "\n";

      // read the plaintext from "messageToEncrypt":
      unsigned char* clear_buf = (unsigned char*)malloc(clear_size);
      if (!clear_buf) { cerr << "Error: malloc returned NULL (message too big?)\n"; exit(1); }
      strcpy((char *)clear_buf,messageToEncrypt.c_str());

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

      cout << "DEBUG| Encrypted message: "<<endl;
      BIO_dump_fp (stdout, (const char *)cphr_buf, cphr_size);

      // delete the symmetric key and the plaintext from memory:
      EVP_CIPHER_CTX_free(ctx);
      #pragma optimize("", off)
      memset(clear_buf, 0, clear_size);
      #pragma optimize("", on)
      free(clear_buf);

      // write the encrypted key, the IV, and the ciphertext into a '.enc' file:
      string cphr_file_name = "encrypted_message.enc";
      FILE* cphr_file = fopen(cphr_file_name.c_str(), "wb");
      if (!cphr_file) { cerr << "Error: cannot open file '" << cphr_file_name << "' (no permissions?)\n"; exit(1); }
      ret = fwrite(encrypted_key, 1, encrypted_key_len, cphr_file);
      if (ret < encrypted_key_len) { cerr << "Error while writing the file '" << cphr_file_name << "'\n"; exit(1); }
      ret = fwrite(iv, 1, EVP_CIPHER_iv_length(cipher), cphr_file);
      if (ret < EVP_CIPHER_iv_length(cipher)) { cerr << "Error while writing the file '" << cphr_file_name << "'\n"; exit(1); }
      ret = fwrite(cphr_buf, 1, cphr_size, cphr_file);
      if (ret < cphr_size) { cerr << "Error while writing the file '" << cphr_file_name << "'\n"; exit(1); }
      fclose(cphr_file);

      cout << "Message encrypted into file '" << cphr_file_name << "'\n";

      // deallocate buffers:
      free(cphr_buf);
      free(encrypted_key);
      free(iv);
      EVP_PKEY_free(pubkey);

      return 0;
    }

    string decrypt(string prvkey_file_name, string cphr_file_name) {
      int ret; // used for return values

      // load my private key:
      FILE* prvkey_file = fopen(prvkey_file_name.c_str(), "r");
      if(!prvkey_file){ cerr << "Error: cannot open file '" << prvkey_file_name << "' (missing?)\n"; exit(1); }
      EVP_PKEY* prvkey = PEM_read_PrivateKey(prvkey_file, NULL, NULL, NULL);
      fclose(prvkey_file);
      if(!prvkey){ cerr << "Error: PEM_read_PrivateKey returned NULL\n"; exit(1); }

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
      int encrypted_key_len = EVP_PKEY_size(prvkey);
      int iv_len = EVP_CIPHER_iv_length(cipher);

      // check for possible integer overflow in (encrypted_key_len + iv_len)
      // (theoretically possible if the encrypted key is too big):
      if(encrypted_key_len > INT_MAX - iv_len) { cerr << "Error: integer overflow (encrypted key too big?)\n"; exit(1); }
      // check for correct format of the encrypted file
      // (size must be >= encrypted key size + IV + 1 block):
      if(cphr_file_size < encrypted_key_len + iv_len) { cerr << "Error: encrypted file with wrong format\n"; exit(1); }

      // allocate buffers for encrypted key, IV, ciphertext, and plaintext:
      unsigned char* encrypted_key = (unsigned char*)malloc(encrypted_key_len);
      unsigned char* iv = (unsigned char*)malloc(iv_len);
      int cphr_size = cphr_file_size - encrypted_key_len - iv_len;
      unsigned char* cphr_buf = (unsigned char*)malloc(cphr_size);
      unsigned char* clear_buf = (unsigned char*)malloc(cphr_size);
      if(!encrypted_key || !iv || !cphr_buf || !clear_buf) { cerr << "Error: malloc returned NULL (file too big?)\n"; exit(1); }

      // read the encrypted key, the IV, and the ciphertext from file:
      ret = fread(encrypted_key, 1, encrypted_key_len, cphr_file);
      if(ret < encrypted_key_len) { cerr << "Error while reading file '" << cphr_file_name << "'\n"; exit(1); }
      ret = fread(iv, 1, iv_len, cphr_file);
      if(ret < iv_len) { cerr << "Error while reading file '" << cphr_file_name << "'\n"; exit(1); }
      ret = fread(cphr_buf, 1, cphr_size, cphr_file);
      if(ret < cphr_size) { cerr << "Error while reading file '" << cphr_file_name << "'\n"; exit(1); }
      fclose(cphr_file);

      // create the envelope context:
      EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
      if(!ctx){ cerr << "Error: EVP_CIPHER_CTX_new returned NULL\n"; exit(1); }

      // decrypt the ciphertext:
      // (perform a single update on the whole ciphertext,
      // assuming that the ciphertext is not huge)
      ret = EVP_OpenInit(ctx, cipher, encrypted_key, encrypted_key_len, iv, prvkey);
      if(ret == 0){ cerr << "Error: EVP_OpenInit returned " << ret << "\n"; exit(1); }
      int nd = 0; // bytes decrypted at each chunk
      int ndtot = 0; // total decrypted bytes
      ret = EVP_OpenUpdate(ctx, clear_buf, &nd, cphr_buf, cphr_size);
      if(ret == 0){ cerr << "Error: EVP_OpenUpdate returned " << ret << "\n"; exit(1); }
      ndtot += nd;
      ret = EVP_OpenFinal(ctx, clear_buf + ndtot, &nd);
      if(ret == 0){ cout << "Error: EVP_OpenFinal returned " << ret << " (corrupted file?)\n"; exit(1); }
      ndtot += nd;
      int clear_size = ndtot;

      // delete the symmetric key and the private key from memory:
      EVP_CIPHER_CTX_free(ctx);
      EVP_PKEY_free(prvkey);

      // convert the plaintext to string:
      string message( reinterpret_cast< char const* >(clear_buf) ) ;

      // delete the plaintext from memory:
      #pragma optimize("", off)
      memset(clear_buf, 0, clear_size);
      #pragma optimize("", on)
      free(clear_buf);

      // deallocate buffers:
      free(encrypted_key);
      free(iv);
      free(cphr_buf);

      //return the message:
      return message;
    }
    
};

int main() {
    AsymmetricEncrypter ae;
    ae.encrypt("public_key.pem", "0000000000000000000000000 iiiiiiiiiiiiiiiiiiiiiiiiiiiii bla bla bla bla mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm");
    string message = ae.decrypt("private_key.pem", "encrypted_message.enc");
    cout << "The decrypted message is: '"<< message << "'\n";

    return 0;
}
