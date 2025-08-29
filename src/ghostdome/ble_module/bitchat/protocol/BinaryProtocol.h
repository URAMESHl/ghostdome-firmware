#pragma once

#ifdef ENABLE_BITCHAT_MESH

#include "ghostdome/ble_module/bitchat/models/BitchatPacket.h"
#include <vector>
#include <memory>
#include <array>
#include <string>

namespace bitchat {

/**
 * Binary Protocol Implementation - BitChat Compatible
 * 
 * Handles encoding/decoding of BitChat packets with:
 * - LZ4 compression for payloads >100 bytes
 * - Traffic analysis resistance via message padding
 * - Big-endian integer encoding (BitChat standard)
 * - TLV encoding for structured data
 */
class BinaryProtocol {
public:
    // Core encoding/decoding
    static std::vector<uint8_t> encode(const BitchatPacket& packet);
    static std::unique_ptr<BitchatPacket> decode(const std::vector<uint8_t>& data);
    
    // Packet factory methods
    static BitchatPacket createTextMessage(const std::array<uint8_t, 8>& senderID,
                                          const std::string& text,
                                          const std::array<uint8_t, 8>& recipientID = SpecialRecipients::BROADCAST);
    
    static BitchatPacket createAnnouncement(const std::array<uint8_t, 8>& senderID,
                                           const std::string& nickname,
                                           const std::array<uint8_t, 32>& noisePublicKey,
                                           const std::array<uint8_t, 32>& signingPublicKey);
    
    static BitchatPacket createLeave(const std::array<uint8_t, 8>& senderID,
                                    const std::string& nickname);
    
    static BitchatPacket createNoiseHandshake(const std::array<uint8_t, 8>& senderID,
                                             const std::array<uint8_t, 8>& recipientID,
                                             const std::vector<uint8_t>& handshakeData);
    
    static BitchatPacket createNoiseEncrypted(const std::array<uint8_t, 8>& senderID,
                                             const std::array<uint8_t, 8>& recipientID,
                                             const std::vector<uint8_t>& encryptedData);
    
    static BitchatPacket createFragment(const std::array<uint8_t, 8>& senderID,
                                       const std::array<uint8_t, 8>& recipientID,
                                       const std::string& messageID,
                                       uint16_t fragmentIndex,
                                       uint16_t totalFragments,
                                       const std::vector<uint8_t>& fragmentData);
    
    // Validation
    static bool validatePacket(const BitchatPacket& packet);
    static size_t calculateEncodedSize(const BitchatPacket& packet);

private:
    // Internal encoding/decoding
    static std::vector<uint8_t> encodeCore(const BitchatPacket& packet);
    static std::unique_ptr<BitchatPacket> decodeCore(const std::vector<uint8_t>& data);
    
    // Byte order utilities
    static void writeUint16BigEndian(std::vector<uint8_t>& buffer, uint16_t value);
    static void writeUint64BigEndian(std::vector<uint8_t>& buffer, uint64_t value);
    static uint16_t readUint16BigEndian(const uint8_t* data);
    static uint64_t readUint64BigEndian(const uint8_t* data);
};

/**
 * TLV (Type-Length-Value) Encoding for structured data
 * Used for identity announcements and configuration data
 */
enum class TLVType : uint8_t {
    NICKNAME = 0x01,
    NOISE_PUBLIC_KEY = 0x10,
    SIGNING_PUBLIC_KEY = 0x11,
    CHANNEL_KEY_HASH = 0x20,
    CAPABILITIES = 0x30,
    METADATA = 0xFF
};

class TLVEncoding {
public:
    struct TLVEntry {
        TLVType type;
        std::vector<uint8_t> value;
        
        // Constructors for common types
        TLVEntry(TLVType t, const std::vector<uint8_t>& v) : type(t), value(v) {}
        TLVEntry(TLVType t, const std::string& s);
        TLVEntry(TLVType t, uint8_t val);
        TLVEntry(TLVType t, uint16_t val);
        TLVEntry(TLVType t, uint32_t val);
        TLVEntry(TLVType t, uint64_t val);
        TLVEntry(TLVType t, const std::array<uint8_t, 32>& arr);
    };
    
    // Encoding/decoding
    static std::vector<uint8_t> encode(const std::vector<TLVEntry>& entries);
    static std::vector<TLVEntry> decode(const std::vector<uint8_t>& data);
    
    // Utility functions
    static const TLVEntry* findEntry(const std::vector<TLVEntry>& entries, TLVType type);
    static std::string extractString(const TLVEntry& entry);
    static uint8_t extractUint8(const TLVEntry& entry);
    static uint16_t extractUint16(const TLVEntry& entry);
    static uint32_t extractUint32(const TLVEntry& entry);
    static uint64_t extractUint64(const TLVEntry& entry);
    static std::array<uint8_t, 32> extractByteArray32(const TLVEntry& entry);
    
    // Identity announcement helpers
    static std::vector<uint8_t> createIdentityAnnouncement(
        const std::string& nickname,
        const std::array<uint8_t, 32>& noisePublicKey,
        const std::array<uint8_t, 32>& signingPublicKey);
    
    static bool parseIdentityAnnouncement(
        const std::vector<uint8_t>& payload,
        std::string& nickname,
        std::array<uint8_t, 32>& noisePublicKey,
        std::array<uint8_t, 32>& signingPublicKey);

private:
    static void encodeEntry(std::vector<uint8_t>& buffer, const TLVEntry& entry);
    static bool decodeEntry(const uint8_t*& data, size_t& remaining, TLVEntry& entry);
};

/**
 * LZ4 Compression Utilities
 * Provides transparent compression for large messages
 */
class CompressionUtil {
public:
    static bool shouldCompress(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> compress(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> decompress(const std::vector<uint8_t>& compressed, size_t originalSize);
};

/**
 * Message Padding for Traffic Analysis Resistance
 * Rounds message sizes to standard block sizes
 */
class MessagePadding {
public:
    static size_t optimalBlockSize(size_t originalSize);
    static std::vector<uint8_t> pad(const std::vector<uint8_t>& data, size_t targetSize);
    static std::vector<uint8_t> unpad(const std::vector<uint8_t>& paddedData);

private:
    static const std::array<size_t, 12> BLOCK_SIZES;
    static uint8_t getPaddingByte(size_t index);
};

} // namespace bitchat

#endif // ENABLE_BITCHAT_MESH