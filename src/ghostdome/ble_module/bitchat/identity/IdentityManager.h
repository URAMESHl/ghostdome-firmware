#pragma once

#ifdef ENABLE_BITCHAT_MESH

#include "ghostdome/ble_module/bitchat/models/BitchatPacket.h"
#include <array>
#include <vector>
#include <string>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <esp_err.h>
#include <esp_random.h>
#include <nvs_flash.h>
#include <nvs.h>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/gcm.h>

namespace bitchat {

/**
 * IdentityManager - BitChat Compatible Identity and Key Management
 * 
 * Manages all cryptographic identities and keys for BitChat mesh networking:
 * - X25519 static key pair for Noise protocol handshakes
 * - Ed25519 key pair for digital signatures on announcements
 * - Channel password derivation using PBKDF2-HMAC-SHA256
 * - Persistent key storage in ESP32 NVS flash
 * - 100% compatible with BitChat Android/iOS key formats
 */
class IdentityManager {
public:
    /**
     * Channel encryption key structure
     */
    struct ChannelKey {
        std::array<uint8_t, 32> key;        // AES-256 key
        std::array<uint8_t, 16> salt;       // Random salt used for derivation
        std::string channelName;            // Channel name this key is for
        uint64_t createdTime;               // When this key was created
        uint32_t iterations;                // PBKDF2 iterations used
        
        ChannelKey() : createdTime(0), iterations(10000) {
            key.fill(0);
            salt.fill(0);
        }
    };
    void asyncSaveToStorage();
    IdentityManager();
    ~IdentityManager();

    // Core initialization
    bool initialize();
    void shutdown();
    bool isInitialized() const { return initialized; }

    // Static key management (X25519 for Noise)
    bool generateNoiseKeys();
    std::array<uint8_t, 32> getNoisePrivateKey() const;
    std::array<uint8_t, 32> getNoisePublicKey() const;
    std::string getNoiseFingerprint() const;

    // Signing key management (Ed25519 for announcements)
    bool generateSigningKeys(); 
    std::array<uint8_t, 64> getSigningPrivateKey() const;
    std::array<uint8_t, 32> getSigningPublicKey() const;
    std::string getSigningFingerprint() const;

    // Identity information
    std::string getIdentityFingerprint() const;
    std::string getPeerID() const;
    void setPeerID(const std::string& peerID);

    // Channel password management
    bool setChannelPassword(const std::string& channelName, const std::string& password);
    bool hasChannelPassword(const std::string& channelName) const;
    bool removeChannelPassword(const std::string& channelName);
    std::vector<std::string> getJoinedChannels() const;

    // Channel message encryption/decryption
    std::vector<uint8_t> encryptChannelMessage(const std::string& channelName, const std::string& message);
    std::string decryptChannelMessage(const std::string& channelName, const std::vector<uint8_t>& encryptedData);

    // Utility functions
    std::vector<uint8_t> signAnnouncement(const std::vector<uint8_t>& announcementData);
    bool verifyAnnouncement(const std::vector<uint8_t>& announcementData, 
                          const std::vector<uint8_t>& signature,
                          const std::array<uint8_t, 32>& publicKey);

    // Key rotation and security
    bool rotateNoiseKeys();
    bool rotateSigningKeys();
    void emergencyWipe();

    // Storage management
    bool saveToStorage();
    bool loadFromStorage();
    void clearStorage();

    // Debug information
    std::string getDebugInfo() const;

private:
    // Internal unlocked methods
    std::string getNoiseFingerprint_unlocked() const;
    std::string getSigningFingerprint_unlocked() const;

    // State
    mutable std::mutex keysMutex;
    bool initialized;
    
    // Noise protocol keys (X25519)
    bool noiseKeysGenerated;
    std::array<uint8_t, 32> noisePrivateKey;
    std::array<uint8_t, 32> noisePublicKey;
    
    // Signing keys (Ed25519)  
    bool signingKeysGenerated;
    std::array<uint8_t, 64> signingPrivateKey;  // Ed25519 private key (64 bytes)
    std::array<uint8_t, 32> signingPublicKey;   // Ed25519 public key (32 bytes)
    
    // Identity
    std::string myPeerID;
    
    // Channel keys
    std::unordered_map<std::string, ChannelKey> channelKeys;
    
    // Storage
    nvs_handle_t nvsHandle;
    static constexpr const char* NVS_NAMESPACE = "bitchat_id";
    
    // Private key generation methods
    bool generateX25519KeyPair();
    bool generateEd25519KeyPair(); 
    
    // Channel crypto methods
    bool deriveChannelKey(const std::string& password, const std::array<uint8_t, 16>& salt,
                         uint32_t iterations, std::array<uint8_t, 32>& key);
    
    bool aesGcmEncrypt(const std::array<uint8_t, 32>& key,
                      const std::vector<uint8_t>& plaintext,
                      std::vector<uint8_t>& ciphertext);
    
    bool aesGcmDecrypt(const std::array<uint8_t, 32>& key,
                      const std::vector<uint8_t>& ciphertext,
                      std::vector<uint8_t>& plaintext);
    
    // Storage keys
    static constexpr const char* NOISE_PRIVATE_KEY = "noise_priv";
    static constexpr const char* NOISE_PUBLIC_KEY = "noise_pub";
    static constexpr const char* SIGNING_PRIVATE_KEY = "sign_priv";
    static constexpr const char* SIGNING_PUBLIC_KEY = "sign_pub";
    static constexpr const char* PEER_ID_KEY = "peer_id";
    static constexpr const char* CHANNEL_KEYS_KEY = "chan_keys";
    
    // Key derivation parameters (matching BitChat Android)
    static constexpr uint32_t DEFAULT_PBKDF2_ITERATIONS = 10000;
    static constexpr size_t PBKDF2_SALT_SIZE = 16;
    static constexpr size_t AES_GCM_TAG_SIZE = 16;
    static constexpr size_t AES_GCM_NONCE_SIZE = 12;
};

} // namespace bitchat

#endif // ENABLE_BITCHAT_MESH