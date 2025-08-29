#ifdef ENABLE_BITCHAT_MESH

#include "MeshComponents.h"
#include "ghostdome/ble_module/bitchat/protocol/BinaryProtocol.h"
#include <esp_log.h>
#include <algorithm>
#include <sstream>

static const char* TAG = "MeshComponents";

namespace bitchat {

// PeerManager Implementation
PeerManager::PeerManager() {
    ESP_LOGI(TAG, "PeerManager initialized");
}

bool PeerManager::addPeer(const std::string& peerID, const std::string& nickname) {
    std::lock_guard<std::mutex> lock(peersMutex);
    
    // Check if peer already exists
    auto it = peers.find(peerID);
    if (it != peers.end()) {
        // Update existing peer
        it->second.nickname = nickname;
        it->second.lastSeen = utils::getCurrentTimestamp();
        return false; // Not a new peer
    }
    
    // Check if we have space for new peers
    if (peers.size() >= MAX_PEERS) {
        // Remove oldest inactive peer
        std::string oldestPeerID;
        uint64_t oldestTime = utils::getCurrentTimestamp();
        
        for (const auto& [id, peer] : peers) {
            if (peer.lastSeen < oldestTime) {
                oldestTime = peer.lastSeen;
                oldestPeerID = id;
            }
        }
        
        if (!oldestPeerID.empty()) {
            peers.erase(oldestPeerID);
            ESP_LOGD(TAG, "Removed oldest peer to make space: %s", oldestPeerID.c_str());
        }
    }
    
    // Add new peer
    peers[peerID] = PeerInfo(peerID, nickname);
    ESP_LOGD(TAG, "Added peer: %s (%s)", nickname.c_str(), peerID.c_str());
    return true; // New peer added
}

void PeerManager::removePeer(const std::string& peerID) {
    std::lock_guard<std::mutex> lock(peersMutex);
    
    auto it = peers.find(peerID);
    if (it != peers.end()) {
        ESP_LOGD(TAG, "Removed peer: %s", it->second.nickname.c_str());
        peers.erase(it);
    }
}

void PeerManager::updatePeerLastSeen(const std::string& peerID) {
    std::lock_guard<std::mutex> lock(peersMutex);
    
    auto it = peers.find(peerID);
    if (it != peers.end()) {
        it->second.lastSeen = utils::getCurrentTimestamp();
    }
}

void PeerManager::updatePeerKeys(const std::string& peerID, 
                                const std::array<uint8_t, 32>& noiseKey,
                                const std::array<uint8_t, 32>& signingKey) {
    std::lock_guard<std::mutex> lock(peersMutex);
    
    auto it = peers.find(peerID);
    if (it != peers.end()) {
        it->second.noisePublicKey = noiseKey;
        it->second.signingPublicKey = signingKey;
        it->second.fingerprint = utils::toHexString(utils::sha256(
            std::vector<uint8_t>(noiseKey.begin(), noiseKey.end())));
    }
}

void PeerManager::setPeerEncryptedSession(const std::string& peerID, bool hasSession) {
    std::lock_guard<std::mutex> lock(peersMutex);
    
    auto it = peers.find(peerID);
    if (it != peers.end()) {
        it->second.hasEncryptedSession = hasSession;
    }
}

bool PeerManager::hasPeer(const std::string& peerID) const {
    std::lock_guard<std::mutex> lock(peersMutex);
    return peers.find(peerID) != peers.end();
}

PeerInfo PeerManager::getPeer(const std::string& peerID) const {
    std::lock_guard<std::mutex> lock(peersMutex);
    
    auto it = peers.find(peerID);
    if (it != peers.end()) {
        return it->second;
    }
    
    return PeerInfo(); // Return empty peer info
}

std::vector<std::string> PeerManager::getActivePeerIDs() const {
    std::lock_guard<std::mutex> lock(peersMutex);
    
    std::vector<std::string> activePeers;
    uint64_t currentTime = utils::getCurrentTimestamp();
    
    for (const auto& [peerID, peer] : peers) {
        if (!peer.isExpired()) {
            activePeers.push_back(peerID);
        }
    }
    
    return activePeers;
}

std::vector<PeerInfo> PeerManager::getAllPeers() const {
    std::lock_guard<std::mutex> lock(peersMutex);
    
    std::vector<PeerInfo> allPeers;
    for (const auto& [peerID, peer] : peers) {
        allPeers.push_back(peer);
    }
    
    return allPeers;
}

size_t PeerManager::getActivePeerCount() const {
    std::lock_guard<std::mutex> lock(peersMutex);
    
    size_t count = 0;
    for (const auto& [peerID, peer] : peers) {
        if (!peer.isExpired()) {
            count++;
        }
    }
    
    return count;
}

void PeerManager::cleanupInactivePeers() {
    std::lock_guard<std::mutex> lock(peersMutex);
    
    auto it = peers.begin();
    size_t removed = 0;
    
    while (it != peers.end()) {
        if (it->second.isExpired(PEER_TIMEOUT_MS)) {
            ESP_LOGD(TAG, "Removing inactive peer: %s", it->second.nickname.c_str());
            it = peers.erase(it);
            removed++;
        } else {
            ++it;
        }
    }
    
    if (removed > 0) {
        ESP_LOGD(TAG, "Cleaned up %d inactive peers", removed);
    }
}

void PeerManager::clearAllPeers() {
    std::lock_guard<std::mutex> lock(peersMutex);
    peers.clear();
    ESP_LOGI(TAG, "Cleared all peers");
}

std::string PeerManager::getDebugInfo() const {
    std::lock_guard<std::mutex> lock(peersMutex);
    
    std::stringstream ss;
    ss << "=== Peer Manager Debug ===\n";
    ss << "Total Peers: " << peers.size() << "/" << MAX_PEERS << "\n";
    ss << "Active Peers: " << getActivePeerCount() << "\n";
    
    for (const auto& [peerID, peer] : peers) {
        ss << "  " << peer.nickname << " (" << peerID.substr(0, 8) << "...): ";
        ss << "age=" << (utils::getCurrentTimestamp() - peer.lastSeen) / 1000 << "s, ";
        ss << "encrypted=" << (peer.hasEncryptedSession ? "YES" : "NO") << "\n";
    }
    
    return ss.str();
}

// MessageRouter Implementation
MessageRouter::MessageRouter() {
    ESP_LOGI(TAG, "MessageRouter initialized");
}

std::string MessageRouter::generateMessageHash(const BitchatPacket& packet) const {
    // Create hash from sender + timestamp + first 32 bytes of payload
    std::vector<uint8_t> hashData;
    hashData.insert(hashData.end(), packet.senderID.begin(), packet.senderID.end());
    
    // Add timestamp
    for (int i = 7; i >= 0; i--) {
        hashData.push_back((packet.timestamp >> (i * 8)) & 0xFF);
    }
    
    // Add partial payload
    size_t payloadHash = std::min(packet.payload.size(), size_t(32));
    hashData.insert(hashData.end(), packet.payload.begin(), packet.payload.begin() + payloadHash);
    
    auto hash = utils::sha256(hashData);
    return utils::toHexString(hash).substr(0, 16); // Use first 16 chars
}

void MessageRouter::recordMessage(const BitchatPacket& packet) {
    std::lock_guard<std::mutex> lock(messagesMutex);
    
    std::string hash = generateMessageHash(packet);
    seenMessages[hash] = MessageRecord(hash);
    
    // Cleanup if too many messages
    if (seenMessages.size() > MAX_SEEN_MESSAGES) {
        cleanupOldMessages();
    }
}

void MessageRouter::recordRelay(const BitchatPacket& packet) {
    std::lock_guard<std::mutex> lock(messagesMutex);
    
    std::string hash = generateMessageHash(packet);
    relayedMessages.insert(hash);
    
    auto it = seenMessages.find(hash);
    if (it != seenMessages.end()) {
        it->second.wasRelayed = true;
    }
    
    // Cleanup if too many relayed messages
    if (relayedMessages.size() > MAX_RELAY_HISTORY) {
        // Remove oldest 25% of relayed messages
        size_t toRemove = MAX_RELAY_HISTORY / 4;
        auto relayIt = relayedMessages.begin();
        for (size_t i = 0; i < toRemove && relayIt != relayedMessages.end(); i++) {
            relayIt = relayedMessages.erase(relayIt);
        }
    }
}

bool MessageRouter::isMessageSeen(const BitchatPacket& packet) const {
    std::lock_guard<std::mutex> lock(messagesMutex);
    
    std::string hash = generateMessageHash(packet);
    return seenMessages.find(hash) != seenMessages.end();
}

bool MessageRouter::shouldRelay(const BitchatPacket& packet, size_t activePeerCount) const {
    std::lock_guard<std::mutex> lock(messagesMutex);
    
    // Don't relay if TTL is too low
    if (packet.ttl <= 1) {
        return false;
    }
    
    // Don't relay if we've already relayed this message
    std::string hash = generateMessageHash(packet);
    if (relayedMessages.find(hash) != relayedMessages.end()) {
        return false;
    }
    
    // Don't relay if no peers to relay to
    if (activePeerCount == 0) {
        return false;
    }
    
    // Probabilistic relaying based on network density
    // Relay more aggressively when fewer peers are active
    float relayProbability = 1.0f;
    if (activePeerCount > 5) {
        relayProbability = 0.7f; // 70% chance with many peers
    } else if (activePeerCount > 2) {
        relayProbability = 0.9f; // 90% chance with few peers  
    }
    
    // Simple random decision (ESP32 doesn't have proper random float)
    uint32_t random = esp_random();
    float randomFloat = (float)(random % 1000) / 1000.0f;
    
    return randomFloat < relayProbability;
}

void MessageRouter::cleanupOldMessages() {
    // Called with mutex already locked
    uint64_t currentTime = utils::getCurrentTimestamp();
    
    auto it = seenMessages.begin();
    size_t removed = 0;
    
    while (it != seenMessages.end()) {
        if ((currentTime - it->second.timestamp) > MESSAGE_MEMORY_MS) {
            it = seenMessages.erase(it);
            removed++;
        } else {
            ++it;
        }
    }
    
    // Also cleanup relayed messages
    // Note: This is simplified - in practice we'd track timestamps for relayed messages too
    if (relayedMessages.size() > MAX_RELAY_HISTORY) {
        size_t toRemove = relayedMessages.size() - MAX_RELAY_HISTORY;
        auto relayIt = relayedMessages.begin();
        for (size_t i = 0; i < toRemove && relayIt != relayedMessages.end(); i++) {
            relayIt = relayedMessages.erase(relayIt);
        }
    }
    
    if (removed > 0) {
        ESP_LOGD(TAG, "Cleaned up %d old messages", removed);
    }
}

void MessageRouter::clearAllMessages() {
    std::lock_guard<std::mutex> lock(messagesMutex);
    seenMessages.clear();
    relayedMessages.clear();
    ESP_LOGI(TAG, "Cleared all message history");
}

std::string MessageRouter::getDebugInfo() const {
    std::lock_guard<std::mutex> lock(messagesMutex);
    
    std::stringstream ss;
    ss << "=== Message Router Debug ===\n";
    ss << "Seen Messages: " << seenMessages.size() << "/" << MAX_SEEN_MESSAGES << "\n";
    ss << "Relayed Messages: " << relayedMessages.size() << "/" << MAX_RELAY_HISTORY << "\n";
    
    return ss.str();
}

// FragmentManager Implementation
FragmentManager::FragmentManager() {
    ESP_LOGI(TAG, "FragmentManager initialized");
}

std::vector<BitchatPacket> FragmentManager::fragmentMessage(const BitchatPacket& packet) {
    std::vector<BitchatPacket> fragments;
    
    if (packet.payload.size() <= MAX_FRAGMENT_SIZE) {
        // No fragmentation needed
        fragments.push_back(packet);
        return fragments;
    }
    
    if (packet.payload.size() > MAX_MESSAGE_SIZE) {
        ESP_LOGW(TAG, "Message too large for fragmentation: %d bytes", packet.payload.size());
        return fragments; // Return empty vector
    }
    
    // Calculate number of fragments needed
    uint16_t totalFragments = (packet.payload.size() + MAX_FRAGMENT_SIZE - 1) / MAX_FRAGMENT_SIZE;
    std::string messageID = utils::generateMessageID();
    
    ESP_LOGD(TAG, "Fragmenting message into %d fragments (ID: %s)", totalFragments, messageID.c_str());
    
    for (uint16_t i = 0; i < totalFragments; i++) {
        size_t offset = i * MAX_FRAGMENT_SIZE;
        size_t fragmentSize = std::min(MAX_FRAGMENT_SIZE, packet.payload.size() - offset);
        
        std::vector<uint8_t> fragmentData(
            packet.payload.begin() + offset,
            packet.payload.begin() + offset + fragmentSize
        );
        
        // Create fragment packet using BinaryProtocol
        auto fragmentPacket = BinaryProtocol::createFragment(
            packet.senderID,
            packet.recipientID,
            messageID,
            i,
            totalFragments,
            fragmentData
        );
        
        fragments.push_back(fragmentPacket);
    }
    
    return fragments;
}

std::vector<uint8_t> FragmentManager::FragmentSet::reassemble() const {
    std::vector<uint8_t> reassembled;
    
    // Calculate total size
    size_t totalSize = 0;
    for (const auto& [index, data] : fragments) {
        totalSize += data.size();
    }
    
    reassembled.reserve(totalSize);
    
    // Reassemble in order
    for (uint16_t i = 0; i < totalFragments; i++) {
        auto it = fragments.find(i);
        if (it != fragments.end()) {
            reassembled.insert(reassembled.end(), it->second.begin(), it->second.end());
        } else {
            ESP_LOGE(TAG, "Missing fragment %d during reassembly", i);
            return {}; // Return empty on error
        }
    }
    
    return reassembled;
}

std::unique_ptr<BitchatPacket> FragmentManager::handleFragment(const BitchatPacket& fragment) {
    if (fragment.type != MessageType::FRAGMENT) {
        return nullptr;
    }
    
    // Parse fragment payload: messageID_length + messageID + fragmentIndex + totalFragments + data
    if (fragment.payload.size() < 5) {
        ESP_LOGW(TAG, "Fragment payload too small");
        return nullptr;
    }
    
    size_t offset = 0;
    uint8_t messageIDLength = fragment.payload[offset++];
    
    if (fragment.payload.size() < 1 + messageIDLength + 4) {
        ESP_LOGW(TAG, "Fragment payload malformed");
        return nullptr;
    }
    
    std::string messageID(fragment.payload.begin() + offset, 
                         fragment.payload.begin() + offset + messageIDLength);
    offset += messageIDLength;
    
    uint16_t fragmentIndex = (fragment.payload[offset] << 8) | fragment.payload[offset + 1];
    offset += 2;
    
    uint16_t totalFragments = (fragment.payload[offset] << 8) | fragment.payload[offset + 1];
    offset += 2;
    
    std::vector<uint8_t> fragmentData(fragment.payload.begin() + offset, fragment.payload.end());
    
    std::lock_guard<std::mutex> lock(fragmentsMutex);
    
    // Find or create fragment set
    auto setIt = fragmentSets.find(messageID);
    if (setIt == fragmentSets.end()) {
        fragmentSets[messageID] = FragmentSet(messageID, fragment.getSenderIDString(), totalFragments);
        setIt = fragmentSets.find(messageID);
    }
    
    FragmentSet& fragmentSet = setIt->second;
    
    // Validate fragment
    if (fragmentIndex >= totalFragments || 
        fragmentSet.totalFragments != totalFragments ||
        fragmentSet.senderID != fragment.getSenderIDString()) {
        ESP_LOGW(TAG, "Invalid fragment received");
        return nullptr;
    }
    
    // Add fragment
    fragmentSet.fragments[fragmentIndex] = fragmentData;
    
    ESP_LOGV(TAG, "Received fragment %d/%d for message %s", 
            fragmentIndex + 1, totalFragments, messageID.c_str());
    
    // Check if complete
    if (fragmentSet.isComplete()) {
        ESP_LOGD(TAG, "Message %s reassembly complete", messageID.c_str());
        
        // Reassemble message
        auto reassembledData = fragmentSet.reassemble();
        if (reassembledData.empty()) {
            fragmentSets.erase(messageID);
            return nullptr;
        }
        
        // Create original packet
        std::unique_ptr<BitchatPacket> originalPacket(new BitchatPacket());
        originalPacket->version = fragment.version;
        originalPacket->type = MessageType::MESSAGE; // Assume text message
        originalPacket->ttl = fragment.ttl;
        originalPacket->timestamp = fragment.timestamp;
        originalPacket->senderID = fragment.senderID;
        originalPacket->recipientID = fragment.recipientID;
        originalPacket->payload = reassembledData;
        originalPacket->hasRecipient = fragment.hasRecipient;
        
        // Cleanup fragment set
        fragmentSets.erase(messageID);
        
        return originalPacket;
    }
    
    return nullptr; // Not yet complete
}

void FragmentManager::cleanupExpiredFragments() {
    std::lock_guard<std::mutex> lock(fragmentsMutex);
    
    auto it = fragmentSets.begin();
    size_t removed = 0;
    
    while (it != fragmentSets.end()) {
        if (it->second.isExpired(FRAGMENT_TIMEOUT_MS)) {
            ESP_LOGD(TAG, "Removing expired fragment set: %s", it->first.c_str());
            it = fragmentSets.erase(it);
            removed++;
        } else {
            ++it;
        }
    }
    
    if (removed > 0) {
        ESP_LOGD(TAG, "Cleaned up %d expired fragment sets", removed);
    }
}

void FragmentManager::clearAllFragments() {
    std::lock_guard<std::mutex> lock(fragmentsMutex);
    fragmentSets.clear();
    ESP_LOGI(TAG, "Cleared all fragments");
}

std::string FragmentManager::getDebugInfo() const {
    std::lock_guard<std::mutex> lock(fragmentsMutex);
    
    std::stringstream ss;
    ss << "=== Fragment Manager Debug ===\n";
    ss << "Active Fragment Sets: " << fragmentSets.size() << "\n";
    
    for (const auto& [messageID, fragmentSet] : fragmentSets) {
        ss << "  " << messageID.substr(0, 8) << "...: ";
        ss << fragmentSet.fragments.size() << "/" << fragmentSet.totalFragments;
        ss << " from " << fragmentSet.senderID.substr(0, 8) << "...\n";
    }
    
    return ss.str();
}

// StoreForward Implementation
StoreForward::StoreForward() {
    ESP_LOGI(TAG, "StoreForward initialized");
}

void StoreForward::cacheMessage(const BitchatPacket& packet, const std::string& targetPeerID) {
    std::lock_guard<std::mutex> lock(cachesMutex);
    
    auto& cache = messageCache[targetPeerID];
    
    // Check cache size limit
    if (cache.size() >= MAX_CACHED_MESSAGES_PER_PEER) {
        // Remove oldest message
        cache.erase(cache.begin());
    }
    
    cache.emplace_back(packet);
    
    ESP_LOGD(TAG, "Cached message for peer %s (cache size: %d)", 
            targetPeerID.c_str(), cache.size());
}

void StoreForward::deliverCachedMessages(const std::string& peerID) {
    std::lock_guard<std::mutex> lock(cachesMutex);
    
    auto it = messageCache.find(peerID);
    if (it == messageCache.end() || it->second.empty()) {
        return; // No cached messages
    }
    
    auto& cache = it->second;
    ESP_LOGD(TAG, "Delivering %d cached messages to %s", cache.size(), peerID.c_str());
    
    // Try to deliver each message
    auto cacheIt = cache.begin();
    while (cacheIt != cache.end()) {
        if (deliveryCallback && deliveryCallback(cacheIt->packet)) {
            ESP_LOGV(TAG, "Delivered cached message to %s", peerID.c_str());
            cacheIt = cache.erase(cacheIt);
        } else {
            cacheIt->deliveryAttempts++;
            if (cacheIt->deliveryAttempts >= MAX_DELIVERY_ATTEMPTS) {
                ESP_LOGW(TAG, "Max delivery attempts reached for cached message");
                cacheIt = cache.erase(cacheIt);
            } else {
                ++cacheIt;
            }
        }
    }
    
    // Remove empty cache entry
    if (cache.empty()) {
        messageCache.erase(it);
    }
}

void StoreForward::cleanupExpiredMessages() {
    std::lock_guard<std::mutex> lock(cachesMutex);
    
    auto it = messageCache.begin();
    size_t totalRemoved = 0;
    
    while (it != messageCache.end()) {
        auto& cache = it->second;
        
        // Remove expired messages from this peer's cache
        auto cacheIt = cache.begin();
        size_t removed = 0;
        
        while (cacheIt != cache.end()) {
            if (cacheIt->isExpired(MESSAGE_CACHE_AGE_MS)) {
                cacheIt = cache.erase(cacheIt);
                removed++;
            } else {
                ++cacheIt;
            }
        }
        
        totalRemoved += removed;
        
        // Remove empty cache entry
        if (cache.empty()) {
            it = messageCache.erase(it);
        } else {
            ++it;
        }
    }
    
    if (totalRemoved > 0) {
        ESP_LOGD(TAG, "Cleaned up %d expired cached messages", totalRemoved);
    }
}

void StoreForward::clearAllCachedMessages() {
    std::lock_guard<std::mutex> lock(cachesMutex);
    messageCache.clear();
    ESP_LOGI(TAG, "Cleared all cached messages");
}

std::string StoreForward::getDebugInfo() const {
    std::lock_guard<std::mutex> lock(cachesMutex);
    
    std::stringstream ss;
    ss << "=== Store and Forward Debug ===\n";
    ss << "Cached Peers: " << messageCache.size() << "\n";
    
    size_t totalMessages = 0;
    for (const auto& [peerID, cache] : messageCache) {
        totalMessages += cache.size();
        ss << "  " << peerID.substr(0, 8) << "...: " << cache.size() << " messages\n";
    }
    
    ss << "Total Cached Messages: " << totalMessages << "\n";
    
    return ss.str();
}

} // namespace bitchat

#endif // ENABLE_BITCHAT_MESH