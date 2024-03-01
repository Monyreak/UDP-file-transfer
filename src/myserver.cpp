#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>
#include <sys/stat.h> 
#include <sys/types.h> 

#define MAX_UDP_PAYLOAD 32768
#define HANDSHAKE_SEQ_NUM -1 // Indicating the handshake packet
#define FIN_SEQ_NUM -2
const int HEADER_SIZE = sizeof(int32_t) + sizeof(uint32_t) + 256 + sizeof(int32_t) + sizeof(bool); // Adjusted for handshake


// Monyreak Kit
// Lab4 Winter 2024
// UCSC CSE156

struct Packet {
  int32_t seqNum;     // Handshake uses -1, data packets use >= 0
  uint32_t fileSize;  // fileSize for handshake
  char filepath[256]; // Filepath used only in handshake packet
  uint32_t dataLen; // Data length, used for both handshake (file size) and data // packets
  bool fin;
  char data[MAX_UDP_PAYLOAD - HEADER_SIZE]; // Data
};

struct ClientState {
  std::ofstream outFile;
  std::string filepath;
  uint32_t fileSize = 0;
  int32_t expectNum = 0;
  bool handshakeCompleted = false;
  bool finAction = false;
};

std::unordered_map<std::string, ClientState> clientStates;

int dropPercentage;

bool shouldNotDrop() { 
  return (rand() % 100) >= dropPercentage;
}

// This function ensures that the directory for the given path exists
void ensureDirectoryExists(const std::string& path) {
    struct stat st = {0};

    if (stat(path.c_str(), &st) == -1) {
        mkdir(path.c_str(), 0777); // Creates the directory with rwx permissions for everyone
    }
}

// This updated function creates all directories up to the final element in the path
void createDirectoriesForPath(const std::string& filepath) {
    std::string dirPath = filepath;
    size_t lastSlashPos = dirPath.find_last_of("/\\");
    if (lastSlashPos != std::string::npos) {
        // Extract directory path
        dirPath = dirPath.substr(0, lastSlashPos);
        ensureDirectoryExists(dirPath);
    }
}

std::string currentTimeInRFC3339() {
  time_t now = time(0);
  struct tm tm = *gmtime(&now);
  char buf[30];
  strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
  return std::string(buf);
}

std::string makeClientKey(const struct sockaddr_in& cliAddr) {
    return std::string(inet_ntoa(cliAddr.sin_addr)) + ":" + std::to_string(ntohs(cliAddr.sin_port));
}

void logPacketEvent(const std::string& eventType, const struct sockaddr_in& cliAddr, int seqNum, int localPort) {

    std::cout << currentTimeInRFC3339() << ", " << localPort << ", "
              << inet_ntoa(cliAddr.sin_addr) << ", " << ntohs(cliAddr.sin_port)
              << ", " << eventType << ", " << seqNum << std::endl;
}


int createAndBindSocket(int port) {
    struct sockaddr_in servaddr;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
      std::cerr << "Error creating socket" << std::endl;
      exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(port);

    if (bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
      perror("Bind failed");
      close(sockfd);
      exit(EXIT_FAILURE);
    }

    std::cout << "Socket successfully created and bound to port " << port
              << std::endl;
    return sockfd;
}

void sendAck(int sockfd, const struct sockaddr_in &cliAddr, int32_t seqNum, int localPort)  {
    logPacketEvent("ACK", cliAddr, seqNum, localPort);
    seqNum = htonl(seqNum);
    sendto(sockfd, &seqNum, sizeof(seqNum), 0, (const struct sockaddr *)&cliAddr, sizeof(cliAddr));
}


void processPacket(const struct sockaddr_in& cliAddr, const Packet& packet, int sockfd, const std::string& rootFolderPath, int localPort) {

    std::string clientKey = makeClientKey(cliAddr);
    ClientState& state = clientStates[clientKey];
    int32_t seqNum = ntohl(packet.seqNum);

    if (seqNum == HANDSHAKE_SEQ_NUM) {

        std::string packetPath = rootFolderPath + packet.filepath;
        uint32_t packetfsize = ntohl(packet.fileSize);

        if (!state.handshakeCompleted){
          state.filepath.assign(rootFolderPath + packet.filepath);
          createDirectoriesForPath(state.filepath);
          state.fileSize = ntohl(packet.fileSize);
          state.expectNum = 0;
          state.handshakeCompleted = true;
          state.outFile.open(state.filepath, std::ofstream::binary);
        } else{
          if (state.filepath != packetPath || state.fileSize != packetfsize) {
            if (state.outFile.is_open()) {
                state.outFile.close();
                std::remove(state.filepath.c_str()); // Delete the old file
            }
            // Reset state to handle new file
            state.filepath.assign(packetPath);
            state.fileSize = packetfsize;
            state.expectNum = 0;
            createDirectoriesForPath(state.filepath);
            state.outFile.open(state.filepath, std::ofstream::binary);
            std::cout << "Handshake restarted with new file for client: " << clientKey << std::endl;
          }
        }
      
        if (shouldNotDrop()) {
          sendAck(sockfd, cliAddr, seqNum, localPort);
        } else {
          logPacketEvent("DROP ACK", cliAddr, seqNum, localPort);
        }
    } else if (!state.finAction && seqNum != HANDSHAKE_SEQ_NUM && seqNum != FIN_SEQ_NUM) {
        // Handle data packet
        if (seqNum == state.expectNum) {
            state.outFile.write(packet.data, ntohl(packet.dataLen));
            state.expectNum++;
            if (shouldNotDrop()) {
              sendAck(sockfd, cliAddr, seqNum, localPort);
            } else {
              logPacketEvent("DROP ACK", cliAddr, seqNum, localPort);
            }
        } else if(seqNum < state.expectNum){
            if (shouldNotDrop()) {
              sendAck(sockfd, cliAddr, seqNum, localPort);
            } else {
              logPacketEvent("DROP ACK", cliAddr, seqNum, localPort);
            }
        } else {
            std::cerr << "Out of order packet received from client: " << clientKey << ", SeqNum: " << ntohl(packet.seqNum) << ", Expected: " << state.expectNum << std::endl;
        }
    } else if(seqNum == FIN_SEQ_NUM && packet.fin){

        if (!state.finAction){
          auto writtenSize = state.outFile.tellp();
          state.outFile.close();
          state.finAction = true;
          state.finAction = true;

          if(writtenSize == static_cast<std::streampos>(state.fileSize)){
            state.outFile.clear();
            std::cerr << "File transfer completed" << std::endl;
          } 
          else {
            std::cerr << "File transfer incomplete or corrupted, deleting file." << std::endl;
            remove(state.filepath.c_str()); 
            state.outFile.clear(); 
          }
        }

        if (shouldNotDrop()) {
          clientStates.erase(clientKey);
          sendAck(sockfd, cliAddr, seqNum, localPort);
        } else {
          logPacketEvent("DROP ACK", cliAddr, seqNum, localPort);
        }
        
    }else{
        logPacketEvent("DROP UNEXPECTED", cliAddr, seqNum, localPort);
    }
}


int main(int argc, char *argv[]) {
  if (argc != 4) {
    std::cerr << "Usage: ./server <port> <drop percentage> <root folder path>" << std::endl;
    return 1;
}

  int port;
  std::string rootFolderPath;

  try {
    port = std::stoi(argv[1]);
    dropPercentage = std::stoi(argv[2]);
  } catch (const std::invalid_argument &ia) {
    std::cerr << "Error: Both port and drop percentage must be valid numbers."
              << std::endl;
    return -1;
  } catch (const std::out_of_range &oor) {
    std::cerr << "Error: Port or drop percentage is out of range." << std::endl;
    return -1;
  }

  // Add additional checks for port number and drop percentage range if needed
  if (port < 1024 || port > 65535) {
    std::cerr << "Error: Port number must be between 1024 and 65535."
              << std::endl;
    return -1;
  }

  if (dropPercentage < 0 || dropPercentage > 100) {
    std::cerr << "Error: Drop percentage must be between 0 and 100."
              << std::endl;
    return -1;
  }
  rootFolderPath = argv[3];

  if (rootFolderPath.back() != '/') {
    rootFolderPath += '/'; // Ensure the path ends with a slash
  }
  ensureDirectoryExists(rootFolderPath);

  srand(time(NULL));
  int sockfd = createAndBindSocket(port);

  struct sockaddr_in cliAddr;
  socklen_t cliLen = sizeof(cliAddr);

  Packet packet;

  while (true) {

    memset(&packet, 0, sizeof(packet));

    int n = recvfrom(sockfd, &packet, sizeof(packet), 0,(struct sockaddr *)&cliAddr, &cliLen);
    if (n <= 0) {
      continue; // Skip iteration if no data is received or an error occurred
    }

    int32_t seqNum = ntohl(packet.seqNum);

    if (!shouldNotDrop()) {
      // Log dropped packet but do not process further
      logPacketEvent("DROP DATA", cliAddr, seqNum, port);
      memset(&packet, 0, sizeof(packet));
      continue;
    }

    
    logPacketEvent("DATA", cliAddr, seqNum, port);
    processPacket(cliAddr, packet, sockfd, rootFolderPath, port);
  }

  close(sockfd);
  return 0;
}
