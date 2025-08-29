#pragma once

#ifdef ENABLE_BITCHAT_MESH

#include <vector>
#include <array>
#include <string>
#include <cstdint>
#include <esp_timer.h>
#include <esp_random.h>
#include <mbedtls/sha256.h>

namespace bitchat {

// Message types (matching BitChat Android exactly)
enum class MessageType : uint8_t {
    ANNOUNCE = 0x01,      // Peer announcement with identity
    MESSAGE = 0x02,       // Text message (broadcast or private)
    LEAVE = 0x03,         // Peer leaving announcement
    NOISE_HANDSHAKE = 0x10, // Noise protocol handshake
    NOISE_ENCRYPTED = 0x11, // Encrypted message via Noise
    FRAGMENT = 0x20,      // Message fragment
    READ_RECEIPT = 0x30   // Read receipt confirmation
};

// Packet flags
namespace PacketFlags {
    static constexpr uint8_t HAS_RECIPIENT = 0x01;
    static constexpr uint8_t HAS_SIGNATURE = 0x02;
    static constexpr uint8_t IS_COMPRESSED = 0x04;
}

// Special recipient addresses
namespace SpecialRecipients {
    extern const std::array<uint8_t, 8> BROADCAST;
}

// Constants (matching BitChat protocol exactly)
static constexpr size_t HEADER_SIZE = 13;
static constexpr size_t SENDER_ID_SIZE = 8;
static constexpr size_t RECIPIENT_ID_SIZE = 8;
static constexpr size_t SIGNATURE_SIZE = 64;
static constexpr size_t MAX_PAYLOAD_SIZE = 4000;
static constexpr uint8_t DEFAULT_TTL = 7;
static constexpr size_t COMPRESSION_THRESHOLD = 100;

/**
 * BitChat Packet Structure - 100% compatible with Android/iOS
 * 
 * Header Format (13 bytes):
 * [Version:1][Type:1][TTL:1][Timestamp:8][Flags:1][PayloadLength:2]
 * 
 * Followed by:
 * [SenderID:8][RecipientID:8?][Payload:N][Signature:64?]
 */
struct BitchatPacket {
    // Header fields
    uint8_t version = 1;
    MessageType type;
    uint8_t ttl = DEFAULT_TTL;
    uint64_t timestamp;
    
    // Addressing
    std::array<uint8_t, 8> senderID;
    std::array<uint8_t, 8> recipientID;
    
    // Content
    std::vector<uint8_t> payload;
    std::vector<uint8_t> signature;
    
    // Flags
    bool hasRecipient = false;
    bool hasSignature = false;
    bool isCompressed = false;
    
    // Constructors
    BitchatPacket() = default;
    
    BitchatPacket(MessageType type, const std::array<uint8_t, 8>& senderID,
                  const std::vector<uint8_t>& payload)
        : type(type), senderID(senderID), payload(payload) {
        timestamp = utils::getCurrentTimestamp();
        recipientID = SpecialRecipients::BROADCAST;
        hasRecipient = false;
    }
    
    BitchatPacket(MessageType type, const std::array<uint8_t, 8>& senderID,
                  const std::array<uint8_t, 8>& recipientID,
                  const std::vector<uint8_t>& payload)
        : type(type), senderID(senderID), recipientID(recipientID), payload(payload) {
        timestamp = utils::getCurrentTimestamp();
        hasRecipient = (recipientID != SpecialRecipients::BROADCAST);
    }
    
    // Utility methods
    std::string getSenderIDString() const {
        return utils::toHexString(senderID);
    }
    
    std::string getRecipientIDString() const {
        return utils::toHexString(recipientID);
    }
    
    bool isBroadcast() const {
        return recipientID == SpecialRecipients::BROADCAST;
    }
    
    bool isDirectedTo(const std::array<uint8_t, 8>& targetID) const {
        return recipientID == targetID;
    }
    
    size_t getEncodedSize() const {
        size_t size = HEADER_SIZE + SENDER_ID_SIZE + payload.size();
        if (hasRecipient) size += RECIPIENT_ID_SIZE;
        if (hasSignature) size += SIGNATURE_SIZE;
        return size;
    }
};

/**
 * Noise Protocol Payload Types (for encrypted messages)
 */
enum class NoisePayloadType : uint8_t {
    PRIVATE_MESSAGE = 0x01,
    READ_RECEIPT = 0x02,
    FILE_TRANSFER = 0x03,    // Future use
    AUDIO_DATA = 0x04        // Future use
};

/**
 * Noise Payload Structure (encrypted content)
 */
struct NoisePayload {
    NoisePayloadType type;
    std::vector<uint8_t> data;
    
    NoisePayload(NoisePayloadType type, const std::vector<uint8_t>& data)
        : type(type), data(data) {}
    
    // Encode payload for encryption
    std::vector<uint8_t> encode() const {
        std::vector<uint8_t> encoded;
        encoded.reserve(1 + data.size());
        encoded.push_back(static_cast<uint8_t>(type));
        encoded.insert(encoded.end(), data.begin(), data.end());
        return encoded;
    }
    
    // Decode payload after decryption
    static std::unique_ptr<NoisePayload> decode(const std::vector<uint8_t>& encoded) {
        if (encoded.empty()) {
            return nullptr;
        }
        
        NoisePayloadType type = static_cast<NoisePayloadType>(encoded[0]);
        std::vector<uint8_t> data(encoded.begin() + 1, encoded.end());
        
        return std::make_unique<NoisePayload>(type, data);
    }
};

/**
 * Utility functions for BitChat protocol
 */
namespace utils {
    
    // Generate current timestamp in milliseconds
    inline uint64_t getCurrentTimestamp() {
        return esp_timer_get_time() / 1000;
    }
    
    // Generate random 8-byte peer ID
    inline std::array<uint8_t, 8> generateRandomPeerID() {
        std::array<uint8_t, 8> id;
        esp_fill_random(id.data(), 8);
        return id;
    }
    
    // Convert byte array to hex string
    template<size_t N>
    inline std::string toHexString(const std::array<uint8_t, N>& data) {
        const char* hex = "0123456789abcdef";
        std::string result;
        result.reserve(N * 2);
        
        for (uint8_t byte : data) {
            result.push_back(hex[byte >> 4]);
            result.push_back(hex[byte & 0x0F]);
        }
        
        return result;
    }
    
    // Convert vector to hex string
    inline std::string toHexString(const std::vector<uint8_t>& data) {
        const char* hex = "0123456789abcdef";
        std::string result;
        result.reserve(data.size() * 2);
        
        for (uint8_t byte : data) {
            result.push_back(hex[byte >> 4]);
            result.push_back(hex[byte & 0x0F]);
        }
        
        return result;
    }
    
    // Convert hex string to peer ID
    inline std::array<uint8_t, 8> fromHexStringToPeerID(const std::string& hexStr) {
        std::array<uint8_t, 8> id = {};
        
        if (hexStr.length() >= 16) {
            for (size_t i = 0; i < 8 && i * 2 + 1 < hexStr.length(); i++) {
                char high = hexStr[i * 2];
                char low = hexStr[i * 2 + 1];
                
                uint8_t highVal = (high >= '0' && high <= '9') ? (high - '0') :
                                 (high >= 'a' && high <= 'f') ? (high - 'a' + 10) :
                                 (high >= 'A' && high <= 'F') ? (high - 'A' + 10) : 0;
                                 
                uint8_t lowVal = (low >= '0' && low <= '9') ? (low - '0') :
                                (low >= 'a' && low <= 'f') ? (low - 'a' + 10) :
                                (low >= 'A' && low <= 'F') ? (low - 'A' + 10) : 0;
                
                id[i] = (highVal << 4) | lowVal;
            }
        }
        
        return id;
    }
    
    // Generate unique message ID
    inline std::string generateMessageID() {
        std::array<uint8_t, 16> id;
        esp_fill_random(id.data(), 16);
        return toHexString(id);
    }
    
    // SHA-256 hash function
    inline std::array<uint8_t, 32> sha256(const std::vector<uint8_t>& data) {
        std::array<uint8_t, 32> hash;
        mbedtls_sha256_context ctx;
        
        mbedtls_sha256_init(&ctx);
        mbedtls_sha256_starts(&ctx, 0); // SHA-256
        mbedtls_sha256_update(&ctx, data.data(), data.size());
        mbedtls_sha256_finish(&ctx, hash.data());
        mbedtls_sha256_free(&ctx);
        
        return hash;
    }
    
} // namespace utils

} // namespace bitchat

#endif // ENABLE_BITCHAT_MESH