// Client connection
#include <arpa/inet.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>

#include <string>

#define MSG_MAX_LEN 4096

class PeerClientConnection {
    int sock = 0, valread;
    struct sockaddr_in address;

   public:
    int initialization(char const *IP_Server, u_int16_t PORT_Server) {
        // Avvia la connessione con il server alla porta PORT_Server (del server),
        // casuale per il client

        if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            cerr << "\nSocket creation error \n"
                 << endl;
            return -1;
        }

        address.sin_family = AF_INET;
        address.sin_port = htons(PORT_Server);

        // Convert IPv4 and IPv6 addresses from text to binary form
        if (inet_pton(AF_INET, IP_Server, &address.sin_addr) <= 0) {
            cerr << "\nInvalid address/ Address not supported \n"
                 << endl;
            return -1;
        }

        if (connect(sock, (struct sockaddr *)&address, sizeof(address)) < 0) {
            cerr << "\nConnection Failed \n"
                 << endl;
            return -1;
        }

        return 0;
    };

    int send_msg(string msg) {
        // Invia il messaggio
        if (send(sock, msg.c_str(), msg.length(), 0) < msg.length()) {
            cerr << "\nSent fewer bytes than expected \n"
                 << endl;
            return -1;
        }
        return 0;
    };

    int send_msg(unsigned char const *msg, unsigned int size) {
        // Invia il messaggio
        if (send(sock, msg, size, 0) < size) {
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
        int bytes_read = read(sock, buffer, MSG_MAX_LEN);
        if (bytes_read < 0) {
            cerr << "\nError in message reading \n"
                 << endl;
            return -1;
        }
        // Manca il carattere di fine stringa
        buffer[bytes_read] = '\0';
        return bytes_read;
    };

    ~PeerClientConnection() {
        // Chiude il socket
        close(sock);
        cout << "Connection closed" << endl;
    }
};