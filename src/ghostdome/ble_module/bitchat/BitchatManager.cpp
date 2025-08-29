#ifdef ENABLE_BITCHAT_MESH

#include "BitchatManager.h"
#include "configuration.h"
#include <Arduino.h>

namespace bitchat {

BitchatManager::BitchatManager() 
    : initialized(false), running(false), lastUpdate(0) {
}

BitchatManager::~BitchatManager() {
    stop();
}

bool BitchatManager::initialize() {
    if (initialized) {
        return true;
    }
    
    LOG_INFO("BitChat: Initializing");
    initialized = true;
    return true;
}

bool BitchatManager::start() {
    if (!initialized) {
        return false;
    }
    
    if (running) {
        return true;
    }
    
    LOG_INFO("BitChat: Starting");
    running = true;
    lastUpdate = millis();
    return true;
}

void BitchatManager::stop() {
    if (!running) {
        return;
    }
    
    LOG_INFO("BitChat: Stopping");
    running = false;
}

void BitchatManager::update() {
    if (!running) {
        return;
    }
    
    unsigned long now = millis();
    if (now - lastUpdate < 50) {
        return;
    }
    
    lastUpdate = now;
}

bool BitchatManager::sendMessage(const std::string& message, const std::string& recipient) {
    if (!running) {
        return false;
    }
    
    LOG_INFO("BitChat: Sending message: %s", message.c_str());
    return true;
}

std::vector<std::string> BitchatManager::getActivePeers() const {
    return {};
}

size_t BitchatManager::getActivePeerCount() const {
    return 0;
}

std::string BitchatManager::getNetworkStatus() const {
    return running ? "Running" : "Stopped";
}

} // namespace bitchat

#endif // ENABLE_BITCHAT_MESH
