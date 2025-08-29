#ifdef ENABLE_BITCHAT_MESH

#include "NoiseProtocol.h"
#include "IdentityManager.h"
#include <esp_log.h>
#include <esp_random.h>
#include <esp_timer.h>
#include <mbedtls/sha256.h>
#include <algorithm>
#include <cstring>

static const char* TAG = "NoiseProtocol";

namespace bitchat {

// Updated NoiseProtocol Implementation with IdentityManager Integration
NoiseProtocol::NoiseProtocol(IdentityManager* idMgr) : identityManager(idMgr) {
    if (!identityManager) {
        ESP_LOGE(TAG, "IdentityManager is required for NoiseProtocol");
        return;
    }
    
    ESP_LOGI(TAG, "NoiseProtocol initialized with IdentityManager integration");
}

NoiseProtocol::~NoiseProtocol() {
    clearAllSessions();
}

bool NoiseProtocol::generateStaticKeys() {
    if (!identityManager || !identityManager->isInitialized()) {
        ESP_LOGE(TAG, "IdentityManager not initialized");
        return false;
    }

    ESP_LOGI(TAG, "Using Noise keys from IdentityManager");
    
    // Keys are now managed by IdentityManager - no need to generate them here
    // This method just verifies that keys are available
    
    auto privateKey = identityManager->getNoisePrivateKey();
    auto publicKey = identityManager->getNoisePublicKey();
    
    // Check if keys are non-zero (valid)
    bool hasValidPrivateKey = false;
    bool hasValidPublicKey = false;
    
    for (size_t i = 0; i < 32; i++) {
        if (privateKey[i] != 0) hasValidPrivateKey = true;
        if (publicKey[i] != 0) hasValidPublicKey = true;
    }
    
    if (!hasValidPrivateKey || !hasValidPublicKey) {
        ESP_LOGE(TAG, "IdentityManager has invalid Noise keys");
        return false;
    }
    
    ESP_LOGI(TAG, "✅ Noise keys loaded from IdentityManager");
    ESP_LOGI(TAG, "Noise Fingerprint: %s", identityManager->getNoiseFingerprint().substr(0, 16).c_str());
    
    return true;
}

std::array<uint8_t, 32> NoiseProtocol::getStaticPublicKey() const {
    if (!identityManager) {
        std::array<uint8_t, 32> empty = {};
        return empty;
    }
    
    return identityManager->getNoisePublicKey();
}

std::string NoiseProtocol::getIdentityFingerprint() const {
    if (!identityManager) {
        return "";
    }
    
    return identityManager->getNoiseFingerprint();
}

bool NoiseProtocol::initiateHandshake(const std::string& peerID) {
    std::lock_guard<std::mutex> lock(sessionsMutex);
    
    auto session = getOrCreateSession(peerID);
    if (!session) {
        return false;
    }
    
    if (session->state != SessionState::NONE) {
        ESP_LOGW(TAG, "Handshake already in progress with %s", peerID.c_str());
        return false;
    }
    
    // Generate ephemeral key pair (simplified)
    esp_fill_random(session->ephemeralPrivateKey.data(), 32);
    esp_fill_random(session->ephemeralPublicKey.data(), 32);
    
    session->state = SessionState::HANDSHAKE_INITIATE;
    session->isInitiator = true;
    session->establishedTime = esp_timer_get_time() / 1000;
    
    ESP_LOGD(TAG, "✅ Initiated handshake with %s using persistent identity", peerID.c_str());
    return true;
}

std::vector<uint8_t> NoiseProtocol::getHandshakeMessage(const std::string& peerID) {
    std::lock_guard<std::mutex> lock(sessionsMutex);
    
    auto it = sessions.find(peerID);
    if (it == sessions.end()) {
        return {};
    }
    
    auto& session = *it->second;
    
    // Create handshake message: ephemeral_public_key + static_public_key
    std::vector<uint8_t> handshakeMsg;
    handshakeMsg.reserve(64); // 32 + 32 bytes
    
    // Add ephemeral public key
    handshakeMsg.insert(handshakeMsg.end(), 
                       session.ephemeralPublicKey.begin(), 
                       session.ephemeralPublicKey.end());
    
    // Add static public key from IdentityManager
    auto staticPubKey = identityManager->getNoisePublicKey();
    handshakeMsg.insert(handshakeMsg.end(), 
                       staticPubKey.begin(), 
                       staticPubKey.end());
    
    ESP_LOGV(TAG, "Created handshake message (%d bytes) for %s", handshakeMsg.size(), peerID.c_str());
    return handshakeMsg;
}

bool NoiseProtocol::processHandshakeMessage(const std::string& peerID, const std::vector<uint8_t>& message) {
    std::lock_guard<std::mutex> lock(sessionsMutex);
    
    auto session = getOrCreateSession(peerID);
    if (!session) {
        return false;
    }
    
    if (message.size() != 64) {
        ESP_LOGW(TAG, "Invalid handshake message size from %s: expected 64, got %d", 
                peerID.c_str(), message.size());
        return false;
    }
    
    // Extract ephemeral and static public keys from peer
    std::copy(message.begin(), message.begin() + 32, session->remoteEphemeralPublicKey.begin());
    std::copy(message.begin() + 32, message.end(), session->remoteStaticPublicKey.begin());
    
    // If we're not the initiator, we need to generate our ephemeral keys
    if (!session->isInitiator && session->state == SessionState::NONE) {
        esp_fill_random(session->ephemeralPrivateKey.data(), 32);
        esp_fill_random(session->ephemeralPublicKey.data(), 32);
        session->state = SessionState::HANDSHAKE_RESPONSE;
        session->establishedTime = esp_timer_get_time() / 1000;
    }
    
    // Perform simplified key exchange (NOT real X25519 DH!)
    // In production, replace with proper X25519 operations
    std::array<uint8_t, 32> sharedSecret1, sharedSecret2;
    
    // DH(ephemeral_local, ephemeral_remote)  
    performDiffieHellman(session->ephemeralPrivateKey, session->remoteEphemeralPublicKey, sharedSecret1);
    
    // DH(static_local, ephemeral_remote) or DH(ephemeral_local, static_remote)
    auto myStaticPrivate = identityManager->getNoisePrivateKey();
    performDiffieHellman(myStaticPrivate, session->remoteEphemeralPublicKey, sharedSecret2);
    
    // Combine shared secrets to derive session keys (simplified)
    std::vector<uint8_t> combinedSecrets;
    combinedSecrets.insert(combinedSecrets.end(), sharedSecret1.begin(), sharedSecret1.end());
    combinedSecrets.insert(combinedSecrets.end(), sharedSecret2.begin(), sharedSecret2.end());
    
    // Derive sending and receiving keys
    hashFunction(combinedSecrets, session->sendingKey);
    
    // Slightly different derivation for receiving key
    combinedSecrets.push_back(0x01);
    hashFunction(combinedSecrets, session->receivingKey);
    
    // Finalize the handshake
    finalizeHandshake(*session);
    
    ESP_LOGD(TAG, "✅ Processed handshake message from %s", peerID.c_str());
    return true;
}

NoiseProtocol::SessionState NoiseProtocol::getSessionState(const std::string& peerID) const {
    std::lock_guard<std::mutex> lock(sessionsMutex);
    
    auto it = sessions.find(peerID);
    if (it != sessions.end()) {
        return it->second->state;
    }
    
    return SessionState::NONE;
}

bool NoiseProtocol::hasEstablishedSession(const std::string& peerID) const {
    std::lock_guard<std::mutex> lock(sessionsMutex);
    
    auto it = sessions.find(peerID);
    if (it != sessions.end()) {
        return it->second->state == SessionState::ESTABLISHED;
    }
    
    return false;
}

void NoiseProtocol::removeSession(const std::string& peerID) {
    std::lock_guard<std::mutex> lock(sessionsMutex);
    sessions.erase(peerID);
    ESP_LOGD(TAG, "Removed Noise session for %s", peerID.c_str());
}

std::vector<uint8_t> NoiseProtocol::encrypt(const std::vector<uint8_t>& plaintext, const std::string& peerID) {
    std::lock_guard<std::mutex> lock(sessionsMutex);
    
    auto it = sessions.find(peerID);
    if (it == sessions.end() || it->second->state != SessionState::ESTABLISHED) {
        ESP_LOGW(TAG, "No established session with %s for encryption", peerID.c_str());
        return {};
    }
    
    auto& session = *it->second;
    std::vector<uint8_t> ciphertext;
    
    // Encrypt using session key
    if (encryptWithKey(session.sendingKey, session.sendingNonce, {}, plaintext, ciphertext)) {
        session.sendingNonce++;
        session.lastUsed = esp_timer_get_time() / 1000;
        
        ESP_LOGV(TAG, "✅ Encrypted message for %s (%d->%d bytes)", 
                peerID.c_str(), plaintext.size(), ciphertext.size());
        return ciphertext;
    }
    
    ESP_LOGW(TAG, "❌ Encryption failed for %s", peerID.c_str());
    return {};
}

std::vector<uint8_t> NoiseProtocol::decrypt(const std::vector<uint8_t>& ciphertext, const std::string& peerID) {
    std::lock_guard<std::mutex> lock(sessionsMutex);
    
    auto it = sessions.find(peerID);
    if (it == sessions.end() || it->second->state != SessionState::ESTABLISHED) {
        ESP_LOGW(TAG, "No established session with %s for decryption", peerID.c_str());
        return {};
    }
    
    auto& session = *it->second;
    std::vector<uint8_t> plaintext;
    
    // Decrypt using session key
    if (decryptWithKey(session.receivingKey, session.receivingNonce, {}, ciphertext, plaintext)) {
        session.receivingNonce++;
        session.lastUsed = esp_timer_get_time() / 1000;
        
        ESP_LOGV(TAG, "✅ Decrypted message from %s (%d->%d bytes)", 
                peerID.c_str(), ciphertext.size(), plaintext.size());
        return plaintext;
    }
    
    ESP_LOGW(TAG, "❌ Decryption failed from %s", peerID.c_str());
    return {};
}

std::string NoiseProtocol::getPeerFingerprint(const std::string& peerID) const {
    std::lock_guard<std::mutex> lock(sessionsMutex);
    
    auto it = sessions.find(peerID);
    if (it != sessions.end() && it->second->state == SessionState::ESTABLISHED) {
        std::vector<uint8_t> pubKeyVec(it->second->remoteStaticPublicKey.begin(), 
                                      it->second->remoteStaticPublicKey.end());
        auto hash = utils::sha256(pubKeyVec);
        return utils::toHexString(hash);
    }
    
    return "";
}

std::vector<std::string> NoiseProtocol::getActiveSessions() const {
    std::lock_guard<std::mutex> lock(sessionsMutex);
    
    std::vector<std::string> activePeers;
    for (const auto& [peerID, session] : sessions) {
        if (session->state == SessionState::ESTABLISHED) {
            activePeers.push_back(peerID);
        }
    }
    
    return activePeers;
}

void NoiseProtocol::cleanupExpiredSessions() {
    std::lock_guard<std::mutex> lock(sessionsMutex);
    
    auto it = sessions.begin();
    size_t removed = 0;
    
    while (it != sessions.end()) {
        if (it->second->isExpired()) {
            ESP_LOGD(TAG, "Removing expired Noise session: %s", it->first.c_str());
            it = sessions.erase(it);
            removed++;
        } else {
            ++it;
        }
    }
    
    if (removed > 0) {
        ESP_LOGD(TAG, "Cleaned up %d expired Noise sessions", removed);
    }
}

std::vector<std::string> NoiseProtocol::getSessionsNeedingRekey() const {
    std::lock_guard<std::mutex> lock(sessionsMutex);
    
    std::vector<std::string> needsRekey;
    for (const auto& [peerID, session] : sessions) {
        if (session->needsRekey()) {
            needsRekey.push_back(peerID);
        }
    }
    
    return needsRekey;
}

bool NoiseProtocol::initiateRekey(const std::string& peerID) {
    removeSession(peerID);
    return initiateHandshake(peerID);
}

void NoiseProtocol::clearAllSessions() {
    std::lock_guard<std::mutex> lock(sessionsMutex);
    sessions.clear();
    ESP_LOGI(TAG, "Cleared all Noise sessions");
}

// Private methods implementation
bool NoiseProtocol::performDiffieHellman(const std::array<uint8_t, 32>& privateKey,
                                        const std::array<uint8_t, 32>& publicKey,
                                        std::array<uint8_t, 32>& output) {
    // SIMPLIFIED: XOR-based operation (NOT real X25519!)
    // TODO: Replace with proper X25519 from rweather/Crypto
    
    for (size_t i = 0; i < 32; i++) {
        output[i] = privateKey[i] ^ publicKey[i] ^ static_cast<uint8_t>(i);
    }
    
    // Add some complexity with SHA256
    std::vector<uint8_t> combined;
    combined.insert(combined.end(), privateKey.begin(), privateKey.end());
    combined.insert(combined.end(), publicKey.begin(), publicKey.end());
    
    std::array<uint8_t, 32> hash;
    hashFunction(combined, hash);
    
    // XOR with hash for better mixing
    for (size_t i = 0; i < 32; i++) {
        output[i] ^= hash[i];
    }
    
    ESP_LOGW(TAG, "⚠️  Using simplified DH - replace with X25519 for production!");
    return true;
}

void NoiseProtocol::hashFunction(const std::vector<uint8_t>& input, std::array<uint8_t, 32>& output) {
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0); // SHA-256
    mbedtls_sha256_update(&ctx, input.data(), input.size());
    mbedtls_sha256_finish(&ctx, output.data());
    mbedtls_sha256_free(&ctx);
}

void NoiseProtocol::hmacFunction(const std::array<uint8_t, 32>& key, 
                                const std::vector<uint8_t>& data,
                                std::array<uint8_t, 32>& output) {
    // SIMPLIFIED: Just hash key + data (NOT real HMAC!)
    // TODO: Replace with proper HMAC-SHA256
    std::vector<uint8_t> combined;
    combined.insert(combined.end(), key.begin(), key.end());
    combined.insert(combined.end(), data.begin(), data.end());
    hashFunction(combined, output);
    
    ESP_LOGW(TAG, "⚠️  Using simplified HMAC - replace with proper HMAC-SHA256 for production!");
}

bool NoiseProtocol::encryptWithKey(const std::array<uint8_t, 32>& key,
                                  uint64_t nonce,
                                  const std::vector<uint8_t>& associatedData,
                                  const std::vector<uint8_t>& plaintext,
                                  std::vector<uint8_t>& ciphertext) {
    // SIMPLIFIED: XOR-based encryption (NOT real AES-GCM!)
    // TODO: Replace with proper AES-256-GCM
    
    ciphertext.resize(plaintext.size() + 8); // +8 for simplified "tag"
    
    // XOR with key and nonce
    for (size_t i = 0; i < plaintext.size(); i++) {
        ciphertext[i] = plaintext[i] ^ key[i % 32] ^ static_cast<uint8_t>(nonce >> (i % 8));
    }
    
    // Add simplified authentication "tag" (just hash of ciphertext)
    std::vector<uint8_t> tagData(ciphertext.begin(), ciphertext.begin() + plaintext.size());
    std::array<uint8_t, 32> hash;
    hashFunction(tagData, hash);
    std::copy(hash.begin(), hash.begin() + 8, ciphertext.begin() + plaintext.size());
    
    ESP_LOGW(TAG, "⚠️  Using simplified encryption - replace with AES-256-GCM for production!");
    return true;
}

bool NoiseProtocol::decryptWithKey(const std::array<uint8_t, 32>& key,
                                  uint64_t nonce,
                                  const std::vector<uint8_t>& associatedData,
                                  const std::vector<uint8_t>& ciphertext,
                                  std::vector<uint8_t>& plaintext) {
    // SIMPLIFIED: XOR-based decryption (same as encryption for XOR)
    // TODO: Replace with proper AES-256-GCM
    
    if (ciphertext.size() < 8) {
        return false;
    }
    
    size_t messageSize = ciphertext.size() - 8;
    plaintext.resize(messageSize);
    
    // Verify simplified "tag" first
    std::vector<uint8_t> tagData(ciphertext.begin(), ciphertext.begin() + messageSize);
    std::array<uint8_t, 32> expectedHash;
    hashFunction(tagData, expectedHash);
    
    // Check if tag matches (simplified)
    for (size_t i = 0; i < 8; i++) {
        if (ciphertext[messageSize + i] != expectedHash[i]) {
            ESP_LOGW(TAG, "Authentication tag mismatch");
            return false;
        }
    }
    
    // XOR to decrypt
    for (size_t i = 0; i < messageSize; i++) {
        plaintext[i] = ciphertext[i] ^ key[i % 32] ^ static_cast<uint8_t>(nonce >> (i % 8));
    }
    
    ESP_LOGW(TAG, "⚠️  Using simplified decryption - replace with AES-256-GCM for production!");
    return true;
}

NoiseProtocol::NoiseSession* NoiseProtocol::getOrCreateSession(const std::string& peerID) {
    auto it = sessions.find(peerID);
    if (it != sessions.end()) {
        return it->second.get();
    }
    
    auto session = std::make_unique<NoiseSession>();
    session->reset();
    
    NoiseSession* sessionPtr = session.get();
    sessions[peerID] = std::move(session);
    
    ESP_LOGV(TAG, "Created new Noise session for %s", peerID.c_str());
    return sessionPtr;
}

void NoiseProtocol::finalizeHandshake(NoiseSession& session) {
    session.state = SessionState::ESTABLISHED;
    session.establishedTime = esp_timer_get_time() / 1000;
    session.lastUsed = session.establishedTime;
    session.sendingNonce = 0;
    session.receivingNonce = 0;
    
    ESP_LOGD(TAG, "✅ Noise handshake finalized - session established");
}

// NoiseSession implementation
void NoiseProtocol::NoiseSession::reset() {
    state = SessionState::NONE;
    ephemeralPrivateKey.fill(0);
    ephemeralPublicKey.fill(0);
    remoteStaticPublicKey.fill(0);
    remoteEphemeralPublicKey.fill(0);
    chainingKey.fill(0);
    handshakeHash.fill(0);
    sendingKey.fill(0);
    receivingKey.fill(0);
    sendingNonce = 0;
    receivingNonce = 0;
    establishedTime = 0;
    lastUsed = 0;
    isInitiator = false;
}

bool NoiseProtocol::NoiseSession::isExpired() const {
    uint64_t currentTime = esp_timer_get_time() / 1000;
    
    if (state == SessionState::ESTABLISHED) {
        // Sessions expire after 24 hours of inactivity
        return (currentTime - lastUsed) > 86400000; // 24 hours in ms
    } else {
        // Handshake sessions expire after 30 seconds
        return (currentTime - establishedTime) > 30000; // 30 seconds in ms
    }
}

bool NoiseProtocol::NoiseSession::needsRekey() const {
    if (state != SessionState::ESTABLISHED) {
        return false;
    }
    
    uint64_t currentTime = esp_timer_get_time() / 1000;
    
    // Rekey after 1 million messages or 1 hour (BitChat Android compatibility)
    return (sendingNonce > 1000000) || 
           (receivingNonce > 1000000) ||
           ((currentTime - establishedTime) > 3600000); // 1 hour in ms
}

} // namespace bitchat

#endif // ENABLE_BITCHAT_MESH