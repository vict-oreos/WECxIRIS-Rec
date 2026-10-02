#include <iostream>
#include <vector>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <cstdint>

#define PORT 3333
#define SERVER_IP "127.0.0.1"

//similar to server sending and receiving functions
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
    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "WSAStartup failed.\n";
        return 1;
    }
    // Create client socket
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        std::cerr << "Socket creation failed.\n";
        WSACleanup();
        return 1;
    }
    // Setup server address structure
    sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr);
    // Connect to server
    if (connect(sock, reinterpret_cast<struct sockaddr*>(&serv_addr), sizeof(serv_addr)) == SOCKET_ERROR) {
        std::cerr << "Connection failed. Make sure the server is running.\n";
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    std::cout << "Connected to server!:\n";

    // Send a few test messages
    std::vector<std::string> test_messages = {"hihi plspls take me into wec systems uwu", "lowk hard task man TT", "but fun and im learning new stuff so yay"};

    for (const auto& msg : test_messages) {
        std::cout << "Sending: " << msg << "\n";
        if (!send_framed_message(sock, 0x01, msg)) {
            std::cerr << "Send failed.\n";
            break;
        }

        // Wait for server acknowledgment
        uint8_t resp_type;
        std::string resp_payload;
        if (recv_framed_message(sock, resp_type, resp_payload)) {
            std::cout << "[Server Response] " << resp_payload << "\n\n";
        } else {
            std::cerr << "Failed to receive response.\n";
            break;
        }
    }

    // Cleanup
    closesocket(sock);
    WSACleanup();
    return 0;
}