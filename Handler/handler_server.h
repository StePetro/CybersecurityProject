#include "../utility.h"


// CERTIFICATO ------------------------------------------------------------------------------------------------------------

int cert_handler(int socket) {
    // Apre il file del certificato
    FILE *cert_file = fopen(CERTIFICATE_PATH, "rb");
    if (!cert_file) {
        cerr << "Error: cannot open file '"
             << CERTIFICATE_PATH
             << "' (no permissions?)\n";
        return -1;
    }

    // Legge la lunghezza del certificato
    fseek(cert_file, 0L, SEEK_END);
    long cert_file_size = ftell(cert_file);
    rewind(cert_file);

    // Alloca una buffer per salvare il certificato in memoria
    unsigned char *certificate_buff = new unsigned char[cert_file_size];

    // Scrive il certificato nel buffer
    if (fread(certificate_buff, 1, cert_file_size, cert_file) < cert_file_size) {
        cerr << "Error while reading file '"
             << CERTIFICATE_PATH
             << "'\n";
        return -1;
    }
    fclose(cert_file);

    // Spedisce il certificato in risposta all'utente
    if (send(socket, certificate_buff, cert_file_size, 0) != cert_file_size) {
        perror("Error in sending the welcome message");
        return -1;
    }

    // Dealloca la memoria del buffer
    delete[] certificate_buff;
    return 0;
}


// LOGIN ------------------------------------------------------------------------------------------------------------

int login_handler(int socket, Json::Value &users, Json::Value &socket_slots, char *buffer, sockaddr_in address, int addrlen, int *client_socket, int i, unsigned char **session_key_list) {
    int bytes_read;
    string username = string(buffer);
    // Nome utente
    username = username.substr(username.find(":") + 1);
    if (users[username].empty()) {
        // Se non è nel json risponde Not Found
        string message = "NF";
        if (send(socket, message.c_str(), message.length(), 0) != message.length()) {
            cerr << "Error in sending the message" << endl;
        }
        return -1;
    }

    if (!users[username]["IP"].empty()) {
        // L'utente è già online
        string message = "AL";
        if (send(socket, message.c_str(), message.length(), 0) != message.length()) {
            cerr << "Error in sending the message" << endl;
        }
        return -1;
    }

    // Altrimenti manda un ACK se presente
    string message = "ACK";
    if (send(socket, message.c_str(), message.length(), 0) != message.length()) {
        cerr << "Error in sending the message" << endl;
        return -1;
    }

    // Legge (nonce_c) dal client
    if ((bytes_read = read(socket, buffer, MSG_MAX_LEN)) == 0) {
        // Disconnessione, print delle informazioni
        getpeername(socket, (struct sockaddr *)&address, (socklen_t *)&addrlen);
        printf("Host disconnected , ip %s , port %d \n",
               inet_ntoa(address.sin_addr), ntohs(address.sin_port));

        // Chiusura socket, marcato con 0 per essere riutilizzato
        close(socket);
        client_socket[i] = 0;
        socket_slots[i] = {};
        return -1;
    }

    // Salvo nonce_c del client
    unsigned char *nonce_c = new unsigned char[NONCE_SIZE];
    memcpy(nonce_c, buffer, NONCE_SIZE);

    // Creo casualmente nonce_s del server
    RAND_poll();
    unsigned char *nonce_s = new unsigned char[NONCE_SIZE];
    RAND_bytes((unsigned char *)&nonce_s[0], NONCE_SIZE);

    // Firma digitale di nonce_c (nel buffer) con la chiave privata del server
    unsigned char *signed_buff;
    uint32_t signed_len = 0;
    if (sign(PRKEY_PATH, (unsigned char *)nonce_c, NONCE_SIZE, signed_buff, signed_len) != 0) {
        cerr << "Not able to sign" << endl;
        return -1;
    }

    // Preparazione messaggio (nonce_s || sgn(nonce_c))
    memcpy(buffer, nonce_s, NONCE_SIZE);
    memcpy(buffer + NONCE_SIZE, signed_buff, signed_len);

    // Invio (nonce_s || sgn(nonce_c)))
    if (send(socket, buffer, signed_len + NONCE_SIZE, 0) != signed_len + NONCE_SIZE) {
        cerr << "Error in sending the message" << endl;
        return -1;
    }

    // Dealloco il messaggio firmato
    delete[] signed_buff;

    // Il client risponde con la firma del nonce del server: sig(nonce_s)
    if ((bytes_read = read(socket, buffer, MSG_MAX_LEN)) == 0) {
        // Disconnessione, print delle informazioni
        getpeername(socket, (struct sockaddr *)&address, (socklen_t *)&addrlen);
        printf("Host disconnected , ip %s , port %d \n",
               inet_ntoa(address.sin_addr), ntohs(address.sin_port));

        // Chiusura socket, marcato con 0 per essere riutilizzato
        close(socket);
        client_socket[i] = 0;
        socket_slots[i] = {};
        return -1;
    }

    // Verifica se la firma sig(nonce_s) è valida, tramite la chiave pubblica dell'utente che si sta loggando
    if (verify_sign(users[username]["pub_key"].asString(), nonce_s, NONCE_SIZE, (unsigned char *)buffer, bytes_read) == 0) {
        string message = "ACK";  // Se era giusta
        if (send(socket, message.c_str(), message.length(), 0) != message.length()) {
            cerr << "Error in sending the message" << endl;
            return -1;
        }
    } else {
        string message = "NV";  // Se non era valida
        if (send(socket, message.c_str(), message.length(), 0) != message.length()) {
            cerr << "Error in sending the message" << endl;
        }
        return -1;
    }

    //INIZIO NEGOZIAZIONE CHIAVE DI SESSIONE -------------------------------------------------------------------------

    EVP_PKEY *keys_server = NULL;  // Sia privata che pubblica
    unsigned char *public_key_server_buf = NULL;
    unsigned int public_key_server_buf_size;

    // Creazione chiavi effimere da parametri standard
    if (create_ephemeral_keys(keys_server) != 0) {
        cerr << "Error in parameters' creation" << endl;
        return -1;
    }

    // Serializzazione chiave pubblica server in un buffer
    if (serialize_pub_key(keys_server, public_key_server_buf, public_key_server_buf_size) != 0) {
        cerr << "Error in parameters' creation" << endl;
        return -1;
    }

    // Incremento di 1 i due nonce
    nonce_add_one(nonce_s);
    nonce_add_one(nonce_c);

    // ( _____ || nonce_c || pubk_s)
    memcpy(buffer + sizeof(uint32_t), nonce_c, NONCE_SIZE);
    memcpy(buffer + sizeof(uint32_t) + NONCE_SIZE, public_key_server_buf, public_key_server_buf_size);

    // Firma digitale di (nonce_c || pubk_s) (nel buffer)
    signed_len = 0;
    if (sign(PRKEY_PATH, (unsigned char *)buffer + sizeof(uint32_t), NONCE_SIZE + public_key_server_buf_size, signed_buff, signed_len) != 0) {
        cerr << "Not able to sign" << endl;
        return -1;
    }

    // ( sgn_len || nonce_c || pubk_s)
    cout << signed_len << endl;
    memcpy(buffer, &signed_len, sizeof(uint32_t));

    // Invio messaggio = (sgn_len || nonce_c || pubk_s || sgn(nonce_c || pubk_s))
    memcpy(buffer + sizeof(uint32_t) + NONCE_SIZE + public_key_server_buf_size, signed_buff, signed_len);
    if (send(socket, buffer, sizeof(uint32_t) + NONCE_SIZE + public_key_server_buf_size + signed_len, 0) != sizeof(uint32_t) + NONCE_SIZE + public_key_server_buf_size + signed_len) {
        cerr << "Error in sending the message" << endl;
        return -1;
    }

    // Ricezione messaggio = (sgn_len || nonce_s || pubk_c || sgn(nonce_s || pubk_c))
    if ((bytes_read = read(socket, buffer, MSG_MAX_LEN)) == 0) {
        // Disconnessione, print delle informazioni
        getpeername(socket, (struct sockaddr *)&address, (socklen_t *)&addrlen);
        printf("Host disconnected , ip %s , port %d \n",
               inet_ntoa(address.sin_addr), ntohs(address.sin_port));

        // Chiusura socket, marcato con 0 per essere riutilizzato
        close(socket);
        client_socket[i] = 0;
        socket_slots[i] = {};
        return -1;
    }

    // Se il nonce è sbagliato chiude la connessione
    if (memcmp(buffer + sizeof(uint32_t), nonce_s, NONCE_SIZE) != 0) {
        cerr << "Wrong nonce" << endl;
        return -1;
    }

    // Prelevo la dimensione della firma
    uint32_t SGN_SIZE = 0;
    memcpy(&SGN_SIZE, buffer, sizeof(uint32_t));
    cout << SGN_SIZE << endl;

    // Controlla la firma, chiude la connessione se sbagliata, buff = (sgn_len || nonce_s || pubk_c || sgn(nonce_s || pubk_c))
    if (verify_sign(users[username]["pub_key"].asString(), (unsigned char *)buffer + sizeof(uint32_t), bytes_read - SGN_SIZE - sizeof(uint32_t), (unsigned char *)buffer + bytes_read - SGN_SIZE, SGN_SIZE) != 0) {
        cerr << "Wrong signature" << endl;
        return -1;
    }

    // Deserializza la chiave pubblica effimera del client, buff = (sgn_len || nonce_s || pubk_c || sgn(nonce_s || pubk_c))
    EVP_PKEY *pub_key_client = NULL;
    deserialize_pub_key((unsigned char *)buffer + NONCE_SIZE + sizeof(uint32_t), bytes_read - SGN_SIZE - NONCE_SIZE - sizeof(uint32_t), pub_key_client);

    // Calcola la chiave di sessione
    unsigned char *session_key;
    if (derive_session_key(keys_server, pub_key_client, session_key) != 0) {
        cerr << "Session key cannot be derived" << endl;
        return -1;
    }

    // Prende le informazioni sull'utente e le salva nella struttura json in memoria (non nel file)
    getpeername(socket, (struct sockaddr *)&address, (socklen_t *)&addrlen);
    users[username]["IP"] = inet_ntoa(address.sin_addr);
    users[username]["PORT"] = ntohs(address.sin_port);

    session_key_list[i] = session_key;
    cout << users << endl;
    // Aggiungo anche l'informazione su quale user sta usando un certo slot dei socket
    socket_slots[i] = username;

    // Dealloco i nonce
    delete[] nonce_s;
    delete[] nonce_c;
    return 0;
}