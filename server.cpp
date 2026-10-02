#include <iostream>
#include <vector>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <cstdint>// fixed width integer types to esnure that data size remains identical and byte layout is maintained (not necessary for running locally on my system but is good practice for bigger projects)
#define PORT 3333// clients have to connect to server's listening port, can be any number above 1024 since 0 to 1024 are Well Known Ports and requires admin privilege to use. In this case, we use 3333 which will be an ephemeral port
// function to ensure all bytes are fully received from the TCP stream
bool recv_all(SOCKET soc, uint8_t* dest, size_t len) { // parameters: (socket descriptor, destination address where incoming data will be saved, length of payload)
    size_t total = 0;
    while (total < len) {// loop will run until full payload has been received so that no message is lost
        int r = recv(soc, reinterpret_cast<char*>(dest + total), len - total, 0);//parametrs: (socket descriptor, buffer, max length allowed, flags)
        if (r <= 0) return false; // error of some sort if r<0 and connection closed if r=0
        total += r;
    }
    return true;
}
// function to ensure all bytes are fully sent over the TCP stream basically just analogous and follows same format as recv_all()
bool send_all(SOCKET sock, const uint8_t* dest, size_t len) { // passing as const to ensure more safety and that nothing gets modified. we don't do that for recv() because we need to write into the memory when we receive a message unlike send
    size_t total = 0;
    while (total < len) {
        int sent = send(sock, reinterpret_cast<const char*>(dest + total), len - total, 0);
        if (sent <= 0) return false;
        total += sent;
    }
    return true;
}
// TLV framing as mentioned in Readme: [1 byte type of message][4 byte length of payload][n byte payload]
bool recv_framed_message(SOCKET sock, uint8_t& out_type, std::string& out_payload) {
    uint8_t type;
    uint32_t len;
    if (!recv_all(sock, &type, 1)) 
        return false;
    if (!recv_all(sock, reinterpret_cast<uint8_t*>(&len), 4))
        return false;
    uint32_t payload_len = ntohl(len);// Convert from network byte order to host byte order basically endianess
    std::vector<char> buffer(payload_len);
    if (!recv_all(sock, reinterpret_cast<uint8_t*>(buffer.data()), payload_len)) 
        return false;
    out_type = type;
    out_payload.assign(buffer.begin(), buffer.end());
    return true;
}
// Analogous sending function
bool send_framed_message(SOCKET sock, uint8_t type, const std::string& payload) {
    uint32_t payload_len = payload.size();
    uint32_t net_len = htonl(payload_len); // convert to network byte order
    // Send Type (1 byte) + Length (4 bytes) + Payload
    if (!send_all(sock, &type, 1)) return false;
    if (!send_all(sock, reinterpret_cast<uint8_t*>(&net_len), 4)) return false;
    if (!send_all(sock, reinterpret_cast<const uint8_t*>(payload.data()), payload_len)) return false;
    return true;
}
int main() {
    // initialize Winsock so that we can use sockets. unlike linux where these functions are built-in, windows requires you to bring in a library
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed.\n";
        return 1;
    }
    // create listening socket
    SOCKET ser = socket(AF_INET, SOCK_STREAM, 0);
    if (ser == INVALID_SOCKET) {
        std::cerr << "Socket creation failed.\n";
        WSACleanup();
        return 1;
    }
    // binding socket meaning attaching socket to a specific local IP address and port number
    sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT); //host to network short

    if (bind(ser, reinterpret_cast<struct sockaddr*>(&address), sizeof(address)) == SOCKET_ERROR) {
        std::cerr << "Bind failed.\n";
        closesocket(ser);
        WSACleanup();
        return 1;
    }

    // Listen for incoming connections
    if (listen(ser, 3) == SOCKET_ERROR) {
        std::cerr << "Listen failed.\n";
        closesocket(ser);
        WSACleanup();
        return 1;
    }

    std::cout << "Server is listening on port " << PORT << "...\n";

    // Accept a client connection
    sockaddr_in client_addr;
    int client_addr_len = sizeof(client_addr);
    SOCKET client_sock = accept(ser, reinterpret_cast<struct sockaddr*>(&client_addr), &client_addr_len);
    if (client_sock == INVALID_SOCKET) {
        std::cerr << "Accept failed.\n";
        closesocket(ser);
        WSACleanup();
        return 1;
    }

    std::cout << "Client connected successfully!\n";

    // Communication loop
    uint8_t msg_type;
    std::string msg_payload;
    while (recv_framed_message(client_sock, msg_type, msg_payload)) {
        std::cout << "[Received] Type: " << static_cast<int>(msg_type) << " | Payload: " << msg_payload << "\n";

        // Echo back a response to the client
        std::string response = "Ack: " + msg_payload;
        if (!send_framed_message(client_sock, 0x01, response)) {
            std::cerr << "Failed to send response.\n";
            break;
        }
    }

    // Cleanup
    closesocket(client_sock);
    closesocket(ser);
    WSACleanup();
    return 0;
}