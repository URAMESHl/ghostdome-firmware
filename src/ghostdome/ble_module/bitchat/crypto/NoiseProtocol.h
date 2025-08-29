#pragma once

#ifdef ENABLE_BITCHAT_MESH

#include "ghostdome/ble_module/bitchat/models/BitchatPacket.h"
#include "ghostdome/ble_module/bitchat/identity/IdentityManager.h"
#include <array>
#include <vector>
#include <string>
#include <memory>
#include <unordered_map>
#include <mutex>

namespace bitchat {

/**
 * Updated Noise Protocol Implementation with IdentityManager Integration
 * 
 * Now properly integrated with IdentityManager for persistent key management:
 * - Uses IdentityManager's X25519 keys instead of generating random ones
 * - Maintains BitChat Android compatibility
 * - Supports proper key rotation
 * - Real persistent identity across reboots
 */
class NoiseProtocol {
public:
    enum class SessionState {
        NONE,
        HANDSHAKE_INITIATE,
        HANDSHAKE_RESPONSE,
        ESTABLISHED
    };

    /**
     * Constructor now requires IdentityManager
     * @param identityManager Pointer to initialized IdentityManager instance
     */
    explicit NoiseProtocol(IdentityManager* identityManager);
    ~NoiseProtocol();

    // Key management (now uses IdentityManager)
    bool generateStaticKeys();
    std::array<uint8_t, 32> getStaticPublicKey() const;
    std::string getIdentityFingerprint() const;

    // Handshake management
    bool initiateHandshake(const std::string& peerID);
    std::vector<uint8_t> getHandshakeMessage(const std::string& peerID);
    bool processHandshakeMessage(const std::string& peerID, const std::vector<uint8_t>& message);
    
    // Session state
    SessionState getSessionState(const std::string& peerID) const;
    bool hasEstablishedSession(const std::string& peerID) const;
    void removeSession(const std::string& peerID);
    
    // Encryption/decryption
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext, const std::string& peerID);
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext, const std::string& peerID);
    
    // Peer management
    std::string getPeerFingerprint(const std::string& peerID) const;
    std::vector<std::string> getActiveSessions() const;
    
    // Maintenance
    void cleanupExpiredSessions();
    std::vector<std::string> getSessionsNeedingRekey() const;
    bool initiateRekey(const std::string& peerID);
    void clearAllSessions();

private:
    struct NoiseSession {
        SessionState state;
        std::array<uint8_t, 32> ephemeralPrivateKey;
        std::array<uint8_t, 32> ephemeralPublicKey;
        std::array<uint8_t, 32> remoteStaticPublicKey;
        std::array<uint8_t, 32> remoteEphemeralPublicKey;
        std::array<uint8_t, 32> chainingKey;
        std::array<uint8_t, 32> handshakeHash;
        std::array<uint8_t, 32> sendingKey;
        std::array<uint8_t, 32> receivingKey;
        uint64_t sendingNonce;
        uint64_t receivingNonce;
        uint64_t establishedTime;
        uint64_t lastUsed;
        bool isInitiator;
        
        void reset();
        bool isExpired() const;
        bool needsRekey() const;
    };

    // IdentityManager reference (owns the keys)
    IdentityManager* identityManager;
    
    // Sessions
    mutable std::mutex sessionsMutex;
    std::unordered_map<std::string, std::unique_ptr<NoiseSession>> sessions;
    
    // Private methods (simplified versions for now)
    bool performDiffieHellman(const std::array<uint8_t, 32>& privateKey,
                             const std::array<uint8_t, 32>& publicKey,
                             std::array<uint8_t, 32>& output);
    
    void hashFunction(const std::vector<uint8_t>& input, std::array<uint8_t, 32>& output);
    void hmacFunction(const std::array<uint8_t, 32>& key, 
                     const std::vector<uint8_t>& data,
                     std::array<uint8_t, 32>& output);
    
    bool encryptWithKey(const std::array<uint8_t, 32>& key,
                       uint64_t nonce,
                       const std::vector<uint8_t>& associatedData,
                       const std::vector<uint8_t>& plaintext,
                       std::vector<uint8_t>& ciphertext);
    
    bool decryptWithKey(const std::array<uint8_t, 32>& key,
                       uint64_t nonce,
                       const std::vector<uint8_t>& associatedData,
                       const std::vector<uint8_t>& ciphertext,
                       std::vector<uint8_t>& plaintext);
    
    NoiseSession* getOrCreateSession(const std::string& peerID);
    void finalizeHandshake(NoiseSession& session);
};

} // namespace bitchat

#endif // ENABLE_BITCHAT_MESH