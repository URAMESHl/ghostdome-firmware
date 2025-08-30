#pragma once

#ifdef ENABLE_BITCHAT_MESH

#include <vector>
#include <string>
#include <functional>
#include <memory>
#include <array>

// Forward declarations
namespace bitchat {
    class BinaryProtocol;
    class PeerManager;
    class MessageRouter;
    class NoiseProtocol;
    class BluetoothManager;
    class FragmentManager;
    class StoreForward;
    class IdentityManager;
    struct BitchatPacket;
    struct PeerInfo;
}

namespace bitchat {

/**
 * BitChat BLE Mesh Service - Main coordinator for mesh networking
 * 100% compatible with BitChat Android/iOS protocol
 * 
 * Now includes complete IdentityManager integration for:
 * - Persistent X25519 keys for Noise protocol
 * - Ed25519 keys for digital signatures
 * - Channel password management with PBKDF2+AES-256-GCM
 * - Cross-platform compatibility
 */
class BitchatMeshService {
public:
    // Message callback types
    using MessageCallback = std::function<void(const std::string& message, const std::string& fromPeerID, bool isPrivate)>;
    using PeerUpdateCallback = std::function<void(const std::vector<std::string>& peerList)>;
    using ConnectionCallback = std::function<void(const std::string& deviceAddress, bool connected)>;
    using DeliveryCallback = std::function<void(const std::string& messageID, const std::string& toPeerID, bool delivered)>;
    using ChannelMessageCallback = std::function<void(const std::string& message, const std::string& fromPeerID, const std::string& channelName)>;

  

    /**
     * Constructor
     */
    BitchatMeshService();

    /**
     * Destructor
     */
    ~BitchatMeshService();

    // Core mesh operations
    bool startMesh(const std::string& deviceName = "GhostDome");
    void stopMesh();
    bool isRunning() const { return isActive; }

    // Identity management (now uses IdentityManager)
    void setNickname(const std::string& nickname);
    std::string getNickname() const { return currentNickname; }
    std::string getMyPeerID() const;
    std::string getIdentityFingerprint() const;

    // Basic messaging
    bool sendBroadcastMessage(const std::string& message);
    bool sendPrivateMessage(const std::string& message, const std::string& targetPeerID);
    
    // Channel management (fully implemented with IdentityManager)
    bool joinChannel(const std::string& channel, const std::string& password = "");
    bool leaveChannel(const std::string& channel);
    bool sendChannelMessage(const std::string& message, const std::string& channel);
    std::vector<std::string> getJoinedChannels() const;
    bool setChannelPassword(const std::string& channel, const std::string& password);
    bool hasChannelPassword(const std::string& channel) const;

    // IRC-style commands (BitChat Android compatible)
    bool processCommand(const std::string& command);
    std::string getCommandHelp() const;

    // Peer management
    std::vector<std::string> getActivePeers() const;
    std::vector<PeerInfo> getPeerInfo() const;
    bool hasEncryptedSession(const std::string& peerID) const;
    void initiateEncryption(const std::string& peerID);

    // Read receipts
    void sendReadReceipt(const std::string& messageID, const std::string& toPeerID);

    // Callbacks
    void setMessageCallback(MessageCallback callback) { messageCallback = callback; }
    void setPeerUpdateCallback(PeerUpdateCallback callback) { peerUpdateCallback = callback; }
    void setConnectionCallback(ConnectionCallback callback) { connectionCallback = callback; }
    void setDeliveryCallback(DeliveryCallback callback) { deliveryCallback = callback; }
    void setChannelMessageCallback(ChannelMessageCallback callback) { channelMessageCallback = callback; }

    // Status and debugging
    struct MeshStatus {
        bool isActive;
        uint32_t messagesSent;
        uint32_t messagesReceived;
        uint32_t messagesRelayed;
        uint32_t activePeers;
        uint32_t encryptedSessions;
        std::string myPeerID;
        std::string myFingerprint;
        std::vector<std::string> joinedChannels;
        bool identityManagerReady;
    };

    MeshStatus getStatus() const;
    std::string getDebugInfo() const;

    // Emergency features (BitChat compatible)
    void emergencyWipe();
    bool rotateIdentity();

private:
    // Core components (now includes IdentityManager)
    std::unique_ptr<IdentityManager> identityManager;
    std::unique_ptr<BinaryProtocol> protocol;
    std::unique_ptr<PeerManager> peerManager;
    std::unique_ptr<MessageRouter> messageRouter;
    std::unique_ptr<NoiseProtocol> noiseProtocol;
    std::unique_ptr<BluetoothManager> bluetoothManager;
    std::unique_ptr<FragmentManager> fragmentManager;
    std::unique_ptr<StoreForward> storeForward;

    // State
    bool isActive;
    std::string currentNickname;

    // Statistics
    mutable uint32_t messagesSent;
    mutable uint32_t messagesReceived;
    mutable uint32_t messagesRelayed;

    // Callbacks
    MessageCallback messageCallback;
    PeerUpdateCallback peerUpdateCallback;
    ConnectionCallback connectionCallback;
    DeliveryCallback deliveryCallback;
    ChannelMessageCallback channelMessageCallback;

    // Internal methods
    void initializeComponents();
    void setupCallbacks();
    void handleIncomingPacket(const BitchatPacket& packet, const std::string& fromDeviceAddress);
    void handlePeerAnnouncement(const BitchatPacket& packet);
    void handleTextMessage(const BitchatPacket& packet);
    void handleEncryptedMessage(const BitchatPacket& packet);
    void handleChannelMessage(const BitchatPacket& packet);
    void handleNoiseHandshake(const BitchatPacket& packet);
    void handleFragmentedMessage(const BitchatPacket& packet);
    void handleLeaveMessage(const BitchatPacket& packet);
    void sendAnnouncement();
    void processMessageQueue();
    void updatePeerList();

    // Channel message helpers
    bool isChannelMessage(const std::string& message, std::string& channelName, std::string& actualMessage);
    std::string formatChannelMessage(const std::string& channel, const std::string& message);

    // IRC-style command processing
    bool processJoinCommand(const std::vector<std::string>& args);
    bool processLeaveCommand(const std::vector<std::string>& args);
    bool processMessageCommand(const std::vector<std::string>& args);
    bool processWhoCommand(const std::vector<std::string>& args);
    bool processBlockCommand(const std::vector<std::string>& args);
    bool processPassCommand(const std::vector<std::string>& args);
    std::vector<std::string> parseCommand(const std::string& command);

    // Disable copy construction and assignment
    BitchatMeshService(const BitchatMeshService&) = delete;
    BitchatMeshService& operator=(const BitchatMeshService&) = delete;
};

} // namespace bitchat

#endif // ENABLE_BITCHAT_MESH