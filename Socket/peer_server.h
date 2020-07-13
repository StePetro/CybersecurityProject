// Server connection
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include <string>

// Il server o il peer in vece di server espongono sempre
// la porta 8888 per permettere la connessione
#define PORT_PEER_SERVER 8888
#define MSG_MAX_LEN 4096

class PeerServerConnection {
    int server_fd, new_socket, valread;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

   public:
    int initialization() {
        // Formatta l'indirizzo del destinatario, sulla porta 8080

        // Creating socket file descriptor
        if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
            cerr << "Error in creating the socket" << endl;
            return -1;
        }
        // Forcefully attaching socket to the port 8080
        if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT,
                       &opt, sizeof(opt))) {
            cerr << "Error in setting socket options" << endl;
            return -1;
        }
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(PORT_PEER_SERVER);
        // Forcefully attaching socket to the port 8080
        if (bind(server_fd, (struct sockaddr *)&address,
                 sizeof(address)) < 0) {
            cerr << "Bind failed" << endl;
            return -1;
        }
        if (listen(server_fd, 3) < 0) {
            cerr << "Error on the listen" << endl;
            return -1;
        }
        cout << "1" << endl;
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address,
                                 (socklen_t *)&addrlen)) < 0) {
            cerr << "Error on the accept" << endl;
            return -1;
        }
        cout << "2" << endl;
        return 0;
    };

    int send_msg(string msg) {
        // Invia la risposta
        if (send(new_socket, msg.c_str(), msg.length(), 0) < msg.length()) {
            cerr << "Sent fewer bytes than expected" << endl;
            return -1;
        }
        return 0;
    };

    int send_msg(unsigned char const *msg, unsigned int size) {
        // Invia il messaggio
        if (send(new_socket, msg, size, 0) < size) {
            cerr << "\nSent fewer bytes than expected \n"
                 << endl;
            return -1;
        }
        return 0;
    };

    int read_msg(unsigned char *buffer) {
        // Copia il messaggio nel buffer, aggiunge il carattere
        // di fine stringa e ritorna il numero di
        // byte letti (carattere di fine stringa escluso)
        int bytes_read = read(new_socket, buffer, MSG_MAX_LEN);
        if (bytes_read < 0) {
            cerr << "Error in message reading" << endl;
            return -1;
        }
        // Manca il carattere di fine stringa
        buffer[bytes_read] = '\0';
        return bytes_read;
    };

    ~PeerServerConnection() {
        // Chiude il socket
        close(server_fd);
        cout << "Connection closed" << endl;
    }
};