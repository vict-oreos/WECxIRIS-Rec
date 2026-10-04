//most of my comment lines and explanations are in the server code. client code is very similar to server code as well since same functions are used
#include <iostream>
#include <vector>
#include <string>
#include <winsock2.h> 
#include <ws2tcpip.h>
#include <cstdint>
#include <random>
#include <thread>
#include <atomic>
using namespace std;

#define PORT 8080
#define SERVER_IP "127.0.0.1"

const uint64_t P = 0xFFFFFFFFFFFFFFC5ULL;
const uint64_t G = 5ULL;

// Same as server all the calc
uint64_t mul_mod(uint64_t a, uint64_t b, uint64_t mod) {
    uint64_t result = 0;
    a %= mod;
    while (b > 0) {
        if (b & 1) {
            if (result >= mod - a) {
                result -= mod;
            }
            result += a;
        }
        if (a >= mod - a) {
            a = 2 * a - mod;
        } else {
            a = 2 * a;
        }
        b >>= 1;
    }
    return result;
}

uint64_t power(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t res = 1;
    base %= mod;
    while (exp > 0) {
        if (exp % 2 == 1) res = mul_mod(res, base, mod);
        base = mul_mod(base, base, mod);
        exp /= 2;
    }
    return res;
}

// KDF also know as Key Derivation Function. uses cryptographic mixing rounds instead of truncation as mentioned in task readme. Truncation usually just refers to cutting the scret key into two and one part if encryption key and the other becomes mac key
void derive_keys(uint64_t key, uint64_t& enc_key, uint64_t& mac_key) {
    uint64_t z1 = key + 0x9e3779b97f4a7c15ULL;// the constant introduced is  agolden ratio constant that will eliminate any patterns that may exist in the secret key
    z1 = (z1 ^ (z1 >> 30)) * 0xbf58476d1ce4e5b9ULL;// randomising it as much as possible, multiplied with a prime number to make it non linear and then the bitwise operations to introduce diffusion 
    z1 = (z1 ^ (z1 >> 27)) * 0x94d049bb133111ebULL;
    enc_key = z1 ^ (z1 >> 31);
    uint64_t z2 = key + 0x9e3779b97f4a7c15ULL + 0x517cc1b727220295ULL;// here we use salting to ensure that enc_key and mac_key are independent of each other 
    z2 = (z2 ^ (z2 >> 30)) * 0xbf58476d1ce4e5b9ULL;
    z2 = (z2 ^ (z2 >> 27)) * 0x94d049bb133111ebULL;
    mac_key = z2 ^ (z2 >> 31);
}

// computing message authentication code
uint64_t compute_mac(const std::string& transcript, uint64_t mac_key) {
    uint64_t hash = 14695981039346656037ULL; // FNV offset basis
    for (char c : transcript) {
        hash ^= static_cast<uint8_t>(c);
        hash *= 1099511628211ULL; // FNV prime
    }
    // mix it with derived mac_key
    uint64_t combined = hash ^ mac_key;
    combined += 0x9e3779b97f4a7c15ULL;
    combined = (combined ^ (combined >> 30)) * 0xbf58476d1ce4e5b9ULL;
    return combined;
}

// we are using a CTR (counter mode-symmetric key encryption mode). this creates a cipher by encrypting counter values and then xoring them with the plaintext (uses nonce as per the bonus)
std::string cipher_transform(const std::string& input, uint64_t enc_key, uint64_t seq) {
    std::string output = input;
    uint64_t state = enc_key ^ seq;
    for (size_t i = 0; i < input.size(); ++i) {
        state ^= (state >> 30);
        state *= 0xbf58476d1ce4e5b9ULL;
        state ^= (state >> 27);
        uint8_t keystream_byte = static_cast<uint8_t>(state & 0xFF);
        output[i] = input[i] ^ keystream_byte;
    }
    return output;
}

//similar to server sending and receiving functions the next 4 are basically the same
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
    vector<char> buffer(payload_len);
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
        cerr << "WSAStartup failed.\n";
        return 1;
    }
    // Create client socket
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
        cerr << "Socket creation failed.\n";
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
        cerr << "Connection failed. Make sure the server is running.\n";
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    std::cout << "Connected to server!\n";
    //LEVEL 2
    //private key for client generation
    random_device rd;
    mt19937_64 gen(rd());
    uniform_int_distribution<uint64_t> dis(2, P - 2);
    uint64_t b_priv = dis(gen);
    uint64_t b_pub = power(G, b_priv, P);

    string client_pub_payload(reinterpret_cast<char*>(&b_pub), sizeof(b_pub));
    // tampering with the code for level 4 verification
    // simulting an attacker intercepting and changing 1 byte of the public key in transit
    // client_pub_payload[0] ^= 0xFF; // flips all bits of the first byte
    if (!send_framed_message(sock, 0x02, client_pub_payload)) {
        cerr << "Failed to send client DH public key.\n";
        return 1;
    }

    uint8_t resp_type;
    string server_pub_str;
    if (!recv_framed_message(sock, resp_type, server_pub_str) || resp_type != 0x02) {
        cerr << "Failed to receive server DH public key.\n";
        return 1;
    }

    uint64_t server_public_key = *reinterpret_cast<const uint64_t*>(server_pub_str.data());

    uint64_t symm_key = power(server_public_key, b_priv, P);

    cout << "[DH Success] Secret key established on client: 0x" <<hex<< symm_key<< "\n\n";

    //LEVEL 3
    uint64_t enc_key = 0;
    uint64_t mac_key = 0;
    derive_keys(symm_key, enc_key, mac_key);
    cout << "[KDF Success] Derived Encryption Key: 0x" << enc_key << "\n";
    cout << "[KDF Success] Derived MAC Key        : 0x" << mac_key << dec << "\n\n";

    // LEVEL 4
    string transcript = client_pub_payload + server_pub_str;
    uint64_t local_mac = compute_mac(transcript, mac_key);
    string client_mac_payload(reinterpret_cast<char*>(&local_mac), sizeof(local_mac));
    if (!send_framed_message(sock, 0x03, client_mac_payload)) {
        cerr << "Failed to send handshake confirmation.\n";
        return 1;
    }
    string server_mac_str;
    if (!recv_framed_message(sock, resp_type, server_mac_str) || resp_type != 0x03) {
        cerr << "Failed to receive handshake confirmation.\n";
        closesocket(sock);
        WSACleanup();
        return 1;
    }
    uint64_t server_mac = *reinterpret_cast<const uint64_t*>(server_mac_str.data());

    if (server_mac != local_mac) {
        cerr << "[SECURITY ALERT] Handshake MAC verification FAILED! Possible tampering detected. Aborting connection.\n";
        closesocket(sock);
        WSACleanup();
        return 1;
    }

    cout << "[Handshake Success] Transcript verified successfully! Secure channel established.\n\n";

    // LEVEL 5 and 6
    atomic<bool> running(true);
    uint64_t send_seq = 0;
    uint64_t recv_seq = 0;

    // Background thread for receiving messages
    thread receiver([sock, enc_key, mac_key, &running, &recv_seq]() {
        uint8_t type;
        string payload;
        while (running && recv_framed_message(sock, type, payload)) {
            if (type != 0x01 || payload.size() < 16) continue;

            uint64_t seq = *reinterpret_cast<const uint64_t*>(payload.data());
            uint64_t mac = *reinterpret_cast<const uint64_t*>(payload.data() + 8);
            string cipher = payload.substr(16);

            if (seq != recv_seq) {
                cerr << "\n[SECURITY ALERT] Sequence mismatch! Closing.\n";
                running = false;
                break;
            }

            string auth(reinterpret_cast<char*>(&seq), 8);
            auth += cipher;
            if (mac != compute_mac(auth, mac_key)) {
                cerr << "\n[SECURITY ALERT] MAC check failed! Closing.\n";
                running = false;
                break;
            }

            string plain = cipher_transform(cipher, enc_key, seq);
            cout << "\n[Server]: " << plain << "\n> " << flush;
            recv_seq++;
        }
        running = false;
    });

    // Main thread for sending messages
    string input;
    cout << "Type messages below (type 'exit' to quit):\n> ";
    while (running && getline(cin, input)) {
        if (input == "exit") break;
        if (input.empty()) continue;

        string cipher = cipher_transform(input, enc_key, send_seq);
        string auth(reinterpret_cast<char*>(&send_seq), 8);
        auth += cipher;
        uint64_t mac = compute_mac(auth, mac_key);

        string packet;
        packet.append(reinterpret_cast<char*>(&send_seq), 8);
        packet.append(reinterpret_cast<char*>(&mac), 8);
        packet.append(cipher);

        if (!send_framed_message(sock, 0x01, packet)) break;
        send_seq++;
        cout << "> ";
    }

    running = false;
    if (receiver.joinable()) receiver.join();

    closesocket(sock);
    WSACleanup();
    return 0;
}