#pragma once

#ifdef ENABLE_BITCHAT_MESH

#include "ghostdome/ble_module/bitchat/models/BitchatPacket.h"
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <mutex>
#include <functional>
#include <array>

namespace bitchat {

/**
 * Peer Information Structure
 */
struct PeerInfo {
    std::string peerID;
    std::string nickname;
    uint64_t lastSeen;
    uint64_t firstSeen;
    bool hasEncryptedSession;
    std::array<uint8_t, 32> noisePublicKey;
    std::array<uint8_t, 32> signingPublicKey;
    std::string fingerprint;
    int8_t rssi;
    uint32_t packetsReceived;
    uint32_t packetsSent;
    
    PeerInfo() = default;
    PeerInfo(const std::string& id, const std::string& name)
        : peerID(id), nickname(name), hasEncryptedSession(false), rssi(-70),
          packetsReceived(0), packetsSent(0) {
        lastSeen = firstSeen = utils::getCurrentTimestamp();
        noisePublicKey.fill(0);
        signingPublicKey.fill(0);
    }
    
    bool isExpired(uint64_t timeoutMs = 30000) const {
        return (utils::getCurrentTimestamp() - lastSeen) > timeoutMs;
    }
};

/**
 * Peer Manager - Tracks active mesh peers
 * Maintains list of up to 50 peers with automatic cleanup
 */
class PeerManager {
public:
    PeerManager();
    ~PeerManager() = default;
    
    // Peer management
    bool addPeer(const std::string& peerID, const std::string& nickname);
    void removePeer(const std::string& peerID);
    void updatePeerLastSeen(const std::string& peerID);
    void updatePeerKeys(const std::string& peerID, 
                       const std::array<uint8_t, 32>& noiseKey,
                       const std::array<uint8_t, 32>& signingKey);
    void setPeerEncryptedSession(const std::string& peerID, bool hasSession);
    
    // Queries
    bool hasPeer(const std::string& peerID) const;
    PeerInfo getPeer(const std::string& peerID) const;
    std::vector<std::string> getActivePeerIDs() const;
    std::vector<PeerInfo> getAllPeers() const;
    size_t getActivePeerCount() const;
    
    // Maintenance
    void cleanupInactivePeers();
    void clearAllPeers();
    
    // Debug
    std::string getDebugInfo() const;

private:
    mutable std::mutex peersMutex;
    std::unordered_map<std::string, PeerInfo> peers;
    static constexpr size_t MAX_PEERS = 50;
    static constexpr uint64_t PEER_TIMEOUT_MS = 30000; // 30 seconds
};

/**
 * Message Router - TTL-based flooding with duplicate detection
 */
class MessageRouter {
public:
    MessageRouter();
    ~MessageRouter() = default;
    
    // Message tracking
    void recordMessage(const BitchatPacket& packet);
    void recordRelay(const BitchatPacket& packet);
    bool isMessageSeen(const BitchatPacket& packet) const;
    bool shouldRelay(const BitchatPacket& packet, size_t activePeerCount) const;
    
    // Maintenance
    void cleanupOldMessages();
    void clearAllMessages();
    
    // Debug
    std::string getDebugInfo() const;

private:
    mutable std::mutex messagesMutex;
    
    struct MessageRecord {
        std::string messageHash;
        uint64_t timestamp;
        bool wasRelayed;
        
        MessageRecord(const std::string& hash) 
            : messageHash(hash), timestamp(utils::getCurrentTimestamp()), wasRelayed(false) {}
    };
    
    std::unordered_map<std::string, MessageRecord> seenMessages;
    std::unordered_set<std::string> relayedMessages;
    
    std::string generateMessageHash(const BitchatPacket& packet) const;
    
    static constexpr size_t MAX_SEEN_MESSAGES = 1000;
    static constexpr size_t MAX_RELAY_HISTORY = 500;
    static constexpr uint64_t MESSAGE_MEMORY_MS = 300000; // 5 minutes
    static constexpr uint64_t RELAY_MEMORY_MS = 60000;    // 1 minute
};

/**
 * Fragment Manager - Message fragmentation and reassembly
 */
class FragmentManager {
public:
    FragmentManager();
    ~FragmentManager() = default;
    
    // Fragmentation
    std::vector<BitchatPacket> fragmentMessage(const BitchatPacket& packet);
    std::unique_ptr<BitchatPacket> handleFragment(const BitchatPacket& fragment);
    
    // Maintenance
    void cleanupExpiredFragments();
    void clearAllFragments();
    
    // Debug
    std::string getDebugInfo() const;

private:
    mutable std::mutex fragmentsMutex;
    
    struct FragmentSet {
        std::string messageID;
        std::string senderID;
        uint16_t totalFragments;
        uint64_t timestamp;
        std::unordered_map<uint16_t, std::vector<uint8_t>> fragments;
        
        FragmentSet(const std::string& msgID, const std::string& sender, uint16_t total)
            : messageID(msgID), senderID(sender), totalFragments(total) {
            timestamp = utils::getCurrentTimestamp();
        }
        
        bool isComplete() const {
            return fragments.size() == totalFragments;
        }
        
        bool isExpired(uint64_t timeoutMs = 30000) const {
            return (utils::getCurrentTimestamp() - timestamp) > timeoutMs;
        }
        
        std::vector<uint8_t> reassemble() const;
    };
    
    std::unordered_map<std::string, FragmentSet> fragmentSets;
    
    static constexpr size_t MAX_FRAGMENT_SIZE = 512;
    static constexpr size_t MAX_MESSAGE_SIZE = 32768; // 32KB
    static constexpr uint64_t FRAGMENT_TIMEOUT_MS = 30000; // 30 seconds
};

/**
 * Store and Forward - Message caching for offline peers
 */
class StoreForward {
public:
    using DeliveryCallback = std::function<bool(const BitchatPacket&)>;
    
    StoreForward();
    ~StoreForward() = default;
    
    // Message caching
    void cacheMessage(const BitchatPacket& packet, const std::string& targetPeerID);
    void deliverCachedMessages(const std::string& peerID);
    
    // Configuration
    void setDeliveryCallback(DeliveryCallback callback) { deliveryCallback = callback; }
    
    // Maintenance
    void cleanupExpiredMessages();
    void clearAllCachedMessages();
    
    // Debug
    std::string getDebugInfo() const;

private:
    mutable std::mutex cachesMutex;
    
    struct CachedMessage {
        BitchatPacket packet;
        uint64_t timestamp;
        uint32_t deliveryAttempts;
        
        CachedMessage(const BitchatPacket& pkt) 
            : packet(pkt), timestamp(utils::getCurrentTimestamp()), deliveryAttempts(0) {}
        
        bool isExpired(uint64_t ageMs = 86400000) const {
            return (utils::getCurrentTimestamp() - timestamp) > ageMs;
        }
    };
    
    std::unordered_map<std::string, std::vector<CachedMessage>> messageCache;
    DeliveryCallback deliveryCallback;
    
    static constexpr size_t MAX_CACHED_MESSAGES_PER_PEER = 100;
    static constexpr uint64_t MESSAGE_CACHE_AGE_MS = 86400000; // 24 hours
    static constexpr uint32_t MAX_DELIVERY_ATTEMPTS = 3;
};

} // namespace bitchat

#endif // ENABLE_BITCHAT_MESH