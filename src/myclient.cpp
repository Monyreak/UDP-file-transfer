#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <ctime>
#include <fstream>
#include <future>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>
#include <regex>
#include <mutex>

using namespace std;

// Monyreak Kit
// Lab4 Winter 2024
// UCSC CSE156

#define MAX_PACKET_SIZE 1024
const int HEADER_SIZE = sizeof(int32_t) + sizeof(uint32_t) + 256 + sizeof(int32_t) + sizeof(bool); // Adjusted for handshake
const int HANDSHAKE_SEQ_NUM = -1;
const int MAX_ATTEMPTS = 10;
int clientLocalPort = 0;

std::mutex coutMutex;
std::mutex cerrMutex;

struct Packet {
  int32_t seqNum;     // Use -1 for handshake   
  uint32_t fileSize;  // fileSize for handshake
  char filepath[256]; // SendPath for handshake
  uint32_t dataLen;
  bool fin;
  char data[MAX_PACKET_SIZE - HEADER_SIZE];
};

struct ServerInfo {
    std::string ip;
    int port;
};

bool isValidIPAddress(const std::string& ip) {
    std::regex ipFormat("^(\\d{1,3}\\.){3}\\d{1,3}$"); // Basic pattern, does not validate value ranges
    return std::regex_match(ip, ipFormat);
}

void safePrint(const std::string& message) {
    std::lock_guard<std::mutex> lock(coutMutex); // Locks the mutex for the current scope
    std::cout << message << std::endl;
    // Mutex is automatically unlocked when lock goes out of scope
    return;
}

void safeErrorLog(const std::string& errorMessage) {
    std::lock_guard<std::mutex> lock(cerrMutex); // Locks the mutex for the current scope
    std::cerr << errorMessage << std::endl;
    // Mutex is automatically unlocked when lock goes out of scope
    return;
}

vector<ServerInfo> parseServerConfig(const string& configFilePath) {
    vector<ServerInfo> servers;
    ifstream configFile(configFilePath);
    string line;
    while (getline(configFile, line)) {
        if (line.empty() || line[0] == '#') continue; // Skip empty lines and comments
        istringstream iss(line);
        ServerInfo serverInfo;
        if (!(iss >> serverInfo.ip >> serverInfo.port)) { 
            safeErrorLog("Invalid server config format.");
            continue; 
            }
        servers.push_back(serverInfo);
    }
    return servers;
}

std::string currentTimeInRFC3339() {
    time_t now = time(0);
    struct tm tm = *gmtime(&now);
    char buf[30];
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return std::string(buf);
}
// Function to initialize the socket and server address structure
int createSocket(const char *serverIP, int serverPort, struct sockaddr_in &servaddr) {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        safeErrorLog("Cannot detect server");
        exit(EXIT_FAILURE);
    }
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(serverPort);
    if (inet_pton(AF_INET, serverIP, &servaddr.sin_addr) <= 0) {
        return -1;
    }
    return sockfd;
}

void logPacketInfo(const char* action, const struct sockaddr_in& serverAddr, int sockfd, 
                   int packetSeqNum, int baseSeqNum, int nextSeqNum, int winsz) {
    // Determine the client's local port if not already known
    if (clientLocalPort == 0) {
        struct sockaddr_in localAddr;
        socklen_t len = sizeof(localAddr);
        if (getsockname(sockfd, (struct sockaddr*)&localAddr, &len) == 0) {
            clientLocalPort = ntohs(localAddr.sin_port);
        }
    }
    // Prepare logging message
    string message = currentTimeInRFC3339() + ", " + to_string(clientLocalPort) + ", " +
                     inet_ntoa(serverAddr.sin_addr) + ", " + to_string(ntohs(serverAddr.sin_port)) + ", " +
                     action + ", " + to_string(packetSeqNum) + ", " + to_string(baseSeqNum) + ", " +
                     to_string(nextSeqNum) + ", " + to_string(baseSeqNum + winsz);
    safePrint(message);
    return;
}


// Function to send the handshake packet
bool sendHandshake(int sockfd, const sockaddr_in &servaddr, const char* outFilePath, uint32_t fileSize, ServerInfo server) {
    Packet packet;
    memset(&packet, 0, sizeof(packet)); // Ensure clean start
    packet.seqNum = htonl(HANDSHAKE_SEQ_NUM);
    packet.fileSize = htonl(fileSize);
    strncpy(packet.filepath, outFilePath, 256);

    int attempts = 0;
    int32_t ackSeqNum = 0;
    socklen_t len = sizeof(servaddr);
    const int MAX_ATTEMPTS = 10; // Try a total of 10 times

    while (attempts < MAX_ATTEMPTS) {
        safePrint("Sending handshake attempt "  + to_string(attempts +1 ) + " "+ server.ip + ":" + std::to_string(server.port));
        ssize_t sentBytes = sendto(sockfd, &packet,
                                   sizeof(packet.seqNum) + sizeof(packet.fileSize) +
                                   strlen(packet.filepath) + 1,
                                   0, (const struct sockaddr*)&servaddr, sizeof(servaddr));
        if (sentBytes < 0) {
            perror("sendto failed");
            continue; // Try sending again
        }

        // Set socket to non-blocking mode for receiving ACK
        struct timeval tv;
        tv.tv_sec = 2; // 2 seconds timeout
        tv.tv_usec = 0;
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

        if (recvfrom(sockfd, &ackSeqNum, sizeof(ackSeqNum), 0,
                     (struct sockaddr*)&servaddr, &len) > 0) {
            ackSeqNum = ntohl(ackSeqNum);
            if (ackSeqNum == HANDSHAKE_SEQ_NUM) {
                safePrint("Handshake ACK received " + server.ip + ":" + std::to_string(server.port));
                return true; // ACK received successfully
            }
        } else {
            // If recvfrom times out, print an informational message (optional)
            if (attempts == MAX_ATTEMPTS - 1) { // Last attempt
                return false; // Indicate failure due to timeout
            }
        }
        attempts++;
    }
    return false; // Handshake failed after all attempts
}


// Function to load the file into packets
vector<Packet> loadFileIntoPackets(const char *filePath, uint32_t mtu) {
    ifstream file(filePath, ifstream::binary);
    if (!file.is_open()) {
        safeErrorLog(std::string("Failed to open file: ") + filePath);
        exit(EXIT_FAILURE);
    }
    vector<Packet> packets;
    uint32_t seqNum = 0;
    while (!file.eof()) {
        Packet packet;
        packet.seqNum = htonl(seqNum++);
        file.read(packet.data, mtu - HEADER_SIZE);
        packet.dataLen = htonl(file.gcount());
        if (file.gcount() > 0) {
        packets.push_back(packet);
        }
    }
    return packets;
}

// Function to send a file packet
void sendFilePacket(int sockfd, const sockaddr_in &servaddr, const Packet &packet) {
    sendto(sockfd, &packet, HEADER_SIZE + ntohl(packet.dataLen), 0, (const struct sockaddr *)&servaddr, sizeof(servaddr));
}

int sendFile(int sockfd, const sockaddr_in &servaddr, vector<Packet> &packets, int winsz) {
    size_t base = 0;
    size_t nextSeqNum = 0;
    const size_t totalPackets = packets.size();
    chrono::steady_clock::time_point timer;
    map<size_t, int> retransmissions; // To track retransmissions for each packet

    while (base < totalPackets) { 
        while (nextSeqNum < totalPackets && nextSeqNum < base + winsz) {
            if (!retransmissions.count(nextSeqNum)) { // If not yet tracked, initialize
                retransmissions[nextSeqNum] = 0;
            }

            // Check for retransmission limit
            if (retransmissions[nextSeqNum] > 10) {
                return 1; 
            }

            if (retransmissions[nextSeqNum] > 0) { // If this is a retransmission
                safeErrorLog("Packet loss detected");
            }

            // Log and send packet
            int packetSeqNum = ntohl(packets[nextSeqNum].seqNum);

            logPacketInfo("DATA", servaddr, sockfd, packetSeqNum, base, nextSeqNum, winsz);
            sendFilePacket(sockfd, servaddr, packets[nextSeqNum]);

            if (base == nextSeqNum) {
                timer = chrono::steady_clock::now();
            }
            nextSeqNum++;
        }

        bool ackReceived = false;
        uint32_t ackSeqNum;
        socklen_t len = sizeof(servaddr);

        while (chrono::steady_clock::now() - timer < chrono::milliseconds(1000)) { // 1-second timeout
            if (recvfrom(sockfd, &ackSeqNum, sizeof(ackSeqNum), MSG_DONTWAIT,(struct sockaddr *)&servaddr, &len) > 0) {

                ackSeqNum = ntohl(ackSeqNum);
                if (ackSeqNum >= base && ackSeqNum < nextSeqNum) {
                    base = ackSeqNum + 1; // Move the window forward
                    logPacketInfo("ACK", servaddr, sockfd, ackSeqNum, base, nextSeqNum, winsz);
                    timer = chrono::steady_clock::now(); // Reset timer for the new base
                    ackReceived = true;
                    break; // Exit the while loop once an ACK is received
                }
            }
        }

        // Handle timeout and retransmission
        if (!ackReceived) {
            safeErrorLog("Timeout. Resending from base: " + to_string(base));
            for (size_t i = base; i < nextSeqNum; ++i) {
                retransmissions[i]++; // Increment retransmission count for each packet
            }
            nextSeqNum = base; // Reset nextSeqNum to resend from base
        }
    }
    return 0;
}

bool sendFin(int sockfd, const sockaddr_in &servaddr,  ServerInfo server) {
    Packet finPacket;
    memset(&finPacket, 0, sizeof(finPacket)); // Clear the packet structure

    finPacket.seqNum = htonl(-2); // Use -2 for FIN packet
    finPacket.fin = true;         // Set FIN flag to true

    int attempts = 0;
    const int MAX_ATTEMPTS = 5;
    int32_t ackSeqNum = 0;
    socklen_t len = sizeof(servaddr);

    while (attempts < MAX_ATTEMPTS) {
        
        safePrint("Sending FIN packet attempt " + to_string(attempts +1 ) + " "+ server.ip + ":" + std::to_string(server.port));
        sendto(sockfd, &finPacket, HEADER_SIZE, 0,(const struct sockaddr *)&servaddr, sizeof(servaddr));

        // Set socket to non-blocking mode for receiving ACK
        struct timeval tv;
        tv.tv_sec = 2; // 2 seconds timeout for ACK reception
        tv.tv_usec = 0;
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&tv, sizeof tv);

        // Attempt to receive the ACK for the FIN packet
        if (recvfrom(sockfd, &ackSeqNum, sizeof(ackSeqNum), 0, (struct sockaddr *)&servaddr, &len) > 0) {
            ackSeqNum = ntohl(ackSeqNum);
            if (ackSeqNum == -2) {
            safePrint("FIN ACK received. File transfer complete " + server.ip + ":" + std::to_string(server.port));
            return true; // ACK for FIN received successfully
            }
        }

        attempts++;
    }

    return false; // Failed to receive ACK for FIN
}

void worker_func(vector<Packet> packets, ServerInfo server, std::promise<int> resultPromise, int winsz, const char* outFilePath, uint32_t fileSize) {
    // Create socket and configure server address
    struct sockaddr_in servaddr;
    int sockfd = createSocket(server.ip.c_str(), server.port, servaddr);
    if (sockfd < 0) {
        safeErrorLog("Socket creation failed for server: " + server.ip + ":" + std::to_string(server.port));
        resultPromise.set_value(1); // Indicate error
        return;
    }

    if (!sendHandshake(sockfd, servaddr, outFilePath, fileSize, server)) {
        safeErrorLog("Cannot detect server " + server.ip + ":" + std::to_string(server.port));
        resultPromise.set_value(1); // Indicate error
        close(sockfd);
        return;
    }

    if (sendFile(sockfd, servaddr, packets, winsz) != 0) {
        safeErrorLog("Reached max re-transmission limit " + server.ip + ":" + std::to_string(server.port));
        resultPromise.set_value(1); // Indicate error
        close(sockfd);
        return;
    }

    if (!sendFin(sockfd, servaddr, server)) {
        safeErrorLog("Reached max re-transmission limit " + server.ip + ":" + std::to_string(server.port));
        resultPromise.set_value(1); // Indicate error
        close(sockfd);
        return;
    }

    close(sockfd);
    resultPromise.set_value(0); // Indicate success
}


int main(int argc, char *argv[]) {

   if (argc < 7) {
        cerr << "Usage: " << argv[0] << " servn servaddr.conf mtu winsz inFilePath outFilePath" << endl;
        return 1;
    }

    uint32_t servn = 0;
    std::string servaddrConf(argv[2]);
    uint32_t mtu;
    int winsz;
    const char *inFilePath = argv[5];
    const char *outFilePath = argv[6];

    vector<ServerInfo> servers = parseServerConfig(servaddrConf);

    if (servers.size() < servn) {
        cerr << "Insufficient servers defined in configuration." << endl;
        return 1;
    }

    try {
        servn = stoi(argv[1]);
        mtu = stoi(argv[3]);
        winsz = stoi(argv[4]);
    } catch (const std::exception &e) {
        cerr << "Error: Invalid input. Server Number, MTU, and window size must be "
                "numbers. Exception: "
            << e.what() << endl;
        return 1;
    }
    if (servn < 1 ){
        cerr << "Error: Server Size must be larger than 0" << endl;
    }

    if (mtu <= HEADER_SIZE || mtu > MAX_PACKET_SIZE) {
        cerr << "Required minimum MTU is " << HEADER_SIZE + 1 << " and less than or equal to " << MAX_PACKET_SIZE << "." << endl;
        return 1;
    }

    if (winsz < 1) {
        cerr << "Error: Window Size must be larger than 0" << endl;
        return 1;
    }

    if (servers.size() != servn) {
        cerr << "Insufficient servers defined in configuration" << endl;
        return 1;
    }

    // Filter servers with invalid IP addresses or port numbers
    std::vector<ServerInfo> validServers;
    for (const auto& server : servers) {
        if (!isValidIPAddress(server.ip) || server.port < 1024 || server.port > 65535) {
            std::cerr << "Invalid server detected and filtered out - IP: " << server.ip << ", Port: " << server.port << std::endl;
            continue; // Skip adding this server to the validServers list
        }
        validServers.push_back(server);
    }
      // Open the input file to read and calculate file size
    ifstream inFile(inFilePath, ifstream::ate | ifstream::binary);
    uint32_t fileSize = inFile.tellg();
    inFile.close(); // Close file after getting size

  // Load the file into packets considering MTU
    vector<Packet> packets = loadFileIntoPackets(inFilePath, mtu);

    std::vector<std::thread> threads;
    std::vector<std::future<int>> results;

    for (auto& server: validServers) {
        std::promise<int> resultPromise;
        results.push_back(resultPromise.get_future());
        threads.emplace_back(worker_func, packets, server, std::move(resultPromise), winsz, outFilePath, fileSize);
    }

    for (auto& t : threads) {
        if (t.joinable()) {
            t.join();
        }
    }

   bool allFailed = true;
    for (auto& result : results) {
        if (result.get() == 0) { // Assuming 0 means success
            allFailed = false;
            break;
        }
    }

    if (allFailed) {
        std::cerr << "Reached max re-transmission limit" << std::endl;
        return 1;
    } else {
        std::cout << "At least one server succeeded. Exiting with success" << std::endl;
        return 0; 
}
    
}
