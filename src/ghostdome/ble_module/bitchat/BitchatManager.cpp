#ifdef ENABLE_BITCHAT_MESH

#include "BitchatManager.h"
#include <esp_log.h>

static const char* TAG = "BitchatManager";

namespace bitchat {

BitchatManager::BitchatManager() 
    : meshService(nullptr), initialized(false) {
    ESP_LOGI(TAG, "BitchatManager created");
}

BitchatManager::~BitchatManager() {
    shutdown();
    ESP_LOGI(TAG, "BitchatManager destroyed");
}

bool BitchatManager::initialize() {
    if (initialized) {
        return true;
    }
    
    ESP_LOGI(TAG, "Initializing BitChat...");
    
    // Create the mesh service
    meshService = std::unique_ptr<BitchatMeshService>();
    if (!meshService) {
        ESP_LOGE(TAG, "Failed to create BitchatMeshService");
        return false;
    }
    
    // Set up callbacks
    meshService->setMessageCallback([this](const std::string& message, const std::string& sender, bool isPrivate) {
        onMeshMessage(message, sender, isPrivate);
    });
    
    meshService->setChannelMessageCallback([this](const std::string& message, const std::string& sender, const std::string& channel) {
        onChannelMessage(message, sender, channel);
    });
    
    initialized = true;
    ESP_LOGI(TAG, "BitChat initialized successfully");
    return true;
}

bool BitchatManager::start(const std::string& deviceName) {
    if (!initialized) {
        ESP_LOGE(TAG, "Cannot start - not initialized");
        return false;
    }
    
    ESP_LOGI(TAG, "Starting BitChat mesh with device name: %s", deviceName.c_str());
    
    return meshService->startMesh(deviceName);
}

void BitchatManager::stop() {
    if (meshService) {
        ESP_LOGI(TAG, "Stopping BitChat mesh");
        meshService->stopMesh();
    }
}

void BitchatManager::shutdown() {
    stop();
    
    if (meshService) {
        meshService.reset();
    }
    
    initialized = false;
    ESP_LOGI(TAG, "BitChat shutdown complete");
}

bool BitchatManager::sendMessage(const std::string& content, const std::string& recipient) {
    if (!meshService || !isRunning()) {
        return false;
    }
    
    if (recipient.empty()) {
        return meshService->sendBroadcastMessage(content);
    } else {
        return meshService->sendPrivateMessage(content, recipient);
    }
}

bool BitchatManager::sendBroadcastMessage(const std::string& content) {
    if (!meshService || !isRunning()) {
        return false;
    }
    
    return meshService->sendBroadcastMessage(content);
}

bool BitchatManager::sendPrivateMessage(const std::string& content, const std::string& recipient) {
    if (!meshService || !isRunning()) {
        return false;
    }
    
    return meshService->sendPrivateMessage(content, recipient);
}

void BitchatManager::setMessageCallback(MessageCallback callback) {
    userMessageCallback = callback;
}

bool BitchatManager::joinChannel(const std::string& channel, const std::string& password) {
    if (!meshService || !isRunning()) {
        return false;
    }
    
    return meshService->joinChannel(channel, password);
}

bool BitchatManager::leaveChannel(const std::string& channel) {
    if (!meshService || !isRunning()) {
        return false;
    }
    
    return meshService->leaveChannel(channel);
}

bool BitchatManager::sendChannelMessage(const std::string& message, const std::string& channel) {
    if (!meshService || !isRunning()) {
        return false;
    }
    
    return meshService->sendChannelMessage(message, channel);
}

std::vector<std::string> BitchatManager::getJoinedChannels() const {
    if (!meshService) {
        return {};
    }
    
    return meshService->getJoinedChannels();
}

std::vector<std::string> BitchatManager::getActivePeers() const {
    if (!meshService) {
        return {};
    }
    
    return meshService->getActivePeers();
}

size_t BitchatManager::getActivePeerCount() const {
    return getActivePeers().size();
}

std::string BitchatManager::getLocalPeerId() const {
    if (!meshService) {
        return "";
    }
    
    return meshService->getMyPeerID();
}

std::string BitchatManager::getNickname() const {
    if (!meshService) {
        return "";
    }
    
    return meshService->getNickname();
}

bool BitchatManager::setNickname(const std::string& nickname) {
    if (!meshService) {
        return false;
    }
    
    meshService->setNickname(nickname);
    return true;
}

bool BitchatManager::isRunning() const {
    return meshService && meshService->isRunning();
}

bool BitchatManager::isInitialized() const {
    return initialized;
}

std::string BitchatManager::getNetworkStatus() const {
    if (!initialized) {
        return "Not Initialized";
    }
    
    if (!isRunning()) {
        return "Stopped";
    }
    
    size_t peers = getActivePeerCount();
    return "Running (" + std::to_string(peers) + " peers)";
}

bool BitchatManager::processCommand(const std::string& command) {
    if (!meshService || !isRunning()) {
        return false;
    }
    
    return meshService->processCommand(command);
}

// Private callback adapters
void BitchatManager::onMeshMessage(const std::string& message, const std::string& sender, bool isPrivate) {
    ESP_LOGD(TAG, "Received %s message from %s: %s", 
             isPrivate ? "private" : "broadcast", 
             sender.c_str(), 
             message.substr(0, 50).c_str());
    
    if (userMessageCallback) {
        userMessageCallback(message, sender, isPrivate);
    }
}

void BitchatManager::onChannelMessage(const std::string& message, const std::string& sender, const std::string& channel) {
    ESP_LOGD(TAG, "Received channel message from %s in #%s: %s", 
             sender.c_str(), 
             channel.c_str(), 
             message.substr(0, 50).c_str());
    
    // Format channel messages for the callback
    std::string formattedMessage = "#" + channel + ": " + message;
    
    if (userMessageCallback) {
        userMessageCallback(formattedMessage, sender, false);
    }
}

} // namespace bitchat

#endif // ENABLE_BITCHAT_MESH
