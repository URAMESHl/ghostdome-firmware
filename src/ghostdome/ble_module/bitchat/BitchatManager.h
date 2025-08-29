#pragma once

#ifdef ENABLE_BITCHAT_MESH

#include "core/BitchatMeshService.h"
#include <string>
#include <vector>
#include <functional>

namespace bitchat {

/**
 * Simple BitchatManager wrapper around BitchatMeshService
 * Provides a clean interface for the existing BitChat implementation
 */
class BitchatManager {
public:
    // Constructor/Destructor
    BitchatManager();
    ~BitchatManager();

    // Core lifecycle
    bool initialize();
    bool start(const std::string& deviceName = "GhostDome");
    void stop();
    void shutdown();

    // Message operations - simple wrappers
    bool sendMessage(const std::string& content, const std::string& recipient = "");
    bool sendBroadcastMessage(const std::string& content);
    bool sendPrivateMessage(const std::string& content, const std::string& recipient);
    
    // Message callback
    typedef std::function<void(const std::string& message, const std::string& sender, bool isPrivate)> MessageCallback;
    void setMessageCallback(MessageCallback callback);

    // Channel operations
    bool joinChannel(const std::string& channel, const std::string& password = "");
    bool leaveChannel(const std::string& channel);
    bool sendChannelMessage(const std::string& message, const std::string& channel);
    std::vector<std::string> getJoinedChannels() const;

    // Peer management
    std::vector<std::string> getActivePeers() const;
    size_t getActivePeerCount() const;

    // Identity
    std::string getLocalPeerId() const;
    std::string getNickname() const;
    bool setNickname(const std::string& nickname);

    // Status
    bool isRunning() const;
    bool isInitialized() const;
    std::string getNetworkStatus() const;

    // Command processing (IRC-style)
    bool processCommand(const std::string& command);

private:
    // The actual BitChat implementation
    std::unique_ptr<BitchatMeshService> meshService;
    
    // State
    bool initialized;
    MessageCallback userMessageCallback;

    // Internal callback adapters
    void onMeshMessage(const std::string& message, const std::string& sender, bool isPrivate);
    void onChannelMessage(const std::string& message, const std::string& sender, const std::string& channel);
};

} // namespace bitchat

#endif // ENABLE_BITCHAT_MESH
