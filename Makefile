# Compiler and compiler flags
CXX = g++
CXXFLAGS = -Wall -g -std=c++11

# Define the source, binary, and executable directories
SRC_DIR = src
BIN_DIR = bin

# Target executable names
SERVER_TARGET = $(BIN_DIR)/myserver
CLIENT_TARGET = $(BIN_DIR)/myclient

# Source files
SERVER_SRC = $(SRC_DIR)/myserver.cpp
CLIENT_SRC = $(SRC_DIR)/myclient.cpp

# Default target
all: $(SERVER_TARGET) $(CLIENT_TARGET)

$(SERVER_TARGET): $(SERVER_SRC)
	$(CXX) $(CXXFLAGS) -o $@ $^

$(CLIENT_TARGET): $(CLIENT_SRC)
	$(CXX) $(CXXFLAGS) -o $@ $^

# Clean target for cleaning up the directory
clean:
	rm -rf $(BIN_DIR)/*

.PHONY: all clean
