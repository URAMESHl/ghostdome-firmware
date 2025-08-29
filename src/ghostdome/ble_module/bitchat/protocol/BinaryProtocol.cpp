#ifdef ENABLE_BITCHAT_MESH

#include "ghostdome/ble_module/bitchat/protocol/BinaryProtocol.h"
#include "ghostdome/ble_module/bitchat/models/BitchatPacket.h"
#include <esp_log.h>
#include <esp_random.h>
#include <esp_lz4.h>  // Proper LZ4 compression library
#include <algorithm>
#include <cstring>

static const char* TAG = "BinaryProtocol";

namespace bitchat {

// BinaryProtocol Implementation with proper LZ4 compression
std::vector<uint8_t> BinaryProtocol::encode(const BitchatPacket& packet) {
    try {
        std::vector<uint8_t> result = encodeCore(packet);
        if (result.empty()) {
            return result;
        }

        // Apply padding to standard block sizes for traffic analysis resistance (matching BitChat)
        size_t optimalSize = MessagePadding::optimalBlockSize(result.size());
        if (optimalSize > result.size()) {
            result = MessagePadding::pad(result, optimalSize);
        }

        return result;
    } catch (const std::exception& e) {
        ESP_LOGE(TAG, "Exception during packet encoding: %s", e.what());
        return {};
    }
}

std::unique_ptr<BitchatPacket> BinaryProtocol::decode(const std::vector<uint8_t>& data) {
    // Try decode as-is first (robust when padding wasn't applied)
    auto packet = decodeCore(data);
    if (packet) {
        return packet;
    }

    // If that fails, try after removing padding
    auto unpadded = MessagePadding::unpad(data);
    if (unpadded != data) {
        return decodeCore(unpadded);
    }

    return nullptr;
}

BitchatPacket BinaryProtocol::createTextMessage(const std::array<uint8_t, 8>& senderID,
                                               const std::string& text,
                                               const std::array<uint8_t, 8>& recipientID) {
    std::vector<uint8_t> payload(text.begin(), text.end());
    
    if (recipientID == SpecialRecipients::BROADCAST) {
        return BitchatPacket(MessageType::MESSAGE, senderID, payload);
    } else {
        return BitchatPacket(MessageType::MESSAGE, senderID, recipientID, payload);
    }
}

BitchatPacket BinaryProtocol::createAnnouncement(const std::array<uint8_t, 8>& senderID,
                                                const std::string& nickname,
                                                const std::array<uint8_t, 32>& noisePublicKey,
                                                const std::array<uint8_t, 32>& signingPublicKey) {
    auto tlvPayload = TLVEncoding::createIdentityAnnouncement(nickname, noisePublicKey, signingPublicKey);
    return BitchatPacket(MessageType::ANNOUNCE, senderID, tlvPayload);
}

BitchatPacket BinaryProtocol::createLeave(const std::array<uint8_t, 8>& senderID,
                                         const std::string& nickname) {
    std::vector<uint8_t> payload(nickname.begin(), nickname.end());
    return BitchatPacket(MessageType::LEAVE, senderID, payload);
}

BitchatPacket BinaryProtocol::createNoiseHandshake(const std::array<uint8_t, 8>& senderID,
                                                  const std::array<uint8_t, 8>& recipientID,
                                                  const std::vector<uint8_t>& handshakeData) {
    return BitchatPacket(MessageType::NOISE_HANDSHAKE, senderID, recipientID, handshakeData);
}

BitchatPacket BinaryProtocol::createNoiseEncrypted(const std::array<uint8_t, 8>& senderID,
                                                  const std::array<uint8_t, 8>& recipientID,
                                                  const std::vector<uint8_t>& encryptedData) {
    return BitchatPacket(MessageType::NOISE_ENCRYPTED, senderID, recipientID, encryptedData);
}

BitchatPacket BinaryProtocol::createFragment(const std::array<uint8_t, 8>& senderID,
                                            const std::array<uint8_t, 8>& recipientID,
                                            const std::string& messageID,
                                            uint16_t fragmentIndex,
                                            uint16_t totalFragments,
                                            const std::vector<uint8_t>& fragmentData) {
    // Create fragment payload: messageID_length + messageID + fragmentIndex + totalFragments + data
    std::vector<uint8_t> payload;
    payload.push_back(static_cast<uint8_t>(messageID.length()));
    payload.insert(payload.end(), messageID.begin(), messageID.end());
    
    writeUint16BigEndian(payload, fragmentIndex);
    writeUint16BigEndian(payload, totalFragments);
    payload.insert(payload.end(), fragmentData.begin(), fragmentData.end());
    
    return BitchatPacket(MessageType::FRAGMENT, senderID, recipientID, payload);
}

bool BinaryProtocol::validatePacket(const BitchatPacket& packet) {
    // Basic validation (matching BitChat Android)
    if (packet.version != 1) {
        return false;
    }
    
    if (packet.ttl == 0) {
        return false;
    }
    
    if (packet.payload.size() > MAX_PAYLOAD_SIZE) {
        return false;
    }
    
    // Validate signature if present
    if (!packet.signature.empty() && packet.signature.size() != SIGNATURE_SIZE) {
        return false;
    }
    
    return true;
}

size_t BinaryProtocol::calculateEncodedSize(const BitchatPacket& packet) {
    size_t size = HEADER_SIZE + SENDER_ID_SIZE;
    
    if (packet.hasRecipient) {
        size += RECIPIENT_ID_SIZE;
    }
    
    if (packet.isCompressed) {
        // Estimate compression savings (rough approximation based on LZ4)
        size += packet.payload.size() * 0.6; // Assume 40% compression (better than previous 30%)
        size += 2; // Original size field
    } else {
        size += packet.payload.size();
    }
    
    if (packet.hasSignature) {
        size += SIGNATURE_SIZE;
    }
    
    return size;
}

std::vector<uint8_t> BinaryProtocol::encodeCore(const BitchatPacket& packet) {
    // Try to compress payload if beneficial (using proper LZ4)
    std::vector<uint8_t> payload = packet.payload;
    uint16_t originalPayloadSize = 0;
    bool isCompressed = false;
    
    if (CompressionUtil::shouldCompress(payload)) {
        auto compressedPayload = CompressionUtil::compress(payload);
        if (!compressedPayload.empty() && compressedPayload.size() < payload.size()) {
            originalPayloadSize = payload.size();
            payload = compressedPayload;
            isCompressed = true;
            ESP_LOGV(TAG, "Compressed payload from %d to %d bytes (%.1f%%)", 
                    originalPayloadSize, payload.size(), 
                    100.0 * payload.size() / originalPayloadSize);
        }
    }
    
    // Calculate total size
    size_t totalSize = HEADER_SIZE + SENDER_ID_SIZE;
    
    bool hasRecipient = (packet.recipientID != SpecialRecipients::BROADCAST);
    bool hasSignature = !packet.signature.empty();
    
    if (hasRecipient) {
        totalSize += RECIPIENT_ID_SIZE;
    }
    
    totalSize += payload.size();
    if (isCompressed) {
        totalSize += 2; // Original size field
    }
    
    if (hasSignature) {
        totalSize += SIGNATURE_SIZE;
    }
    
    // Allocate buffer
    std::vector<uint8_t> buffer;
    buffer.reserve(totalSize);
    
    // Header (13 bytes) - matching BitChat exactly
    buffer.push_back(packet.version);
    buffer.push_back(static_cast<uint8_t>(packet.type));
    buffer.push_back(packet.ttl);
    
    // Timestamp (8 bytes, big-endian)
    writeUint64BigEndian(buffer, packet.timestamp);
    
    // Flags (1 byte)
    uint8_t flags = 0;
    if (hasRecipient) flags |= PacketFlags::HAS_RECIPIENT;
    if (hasSignature) flags |= PacketFlags::HAS_SIGNATURE;
    if (isCompressed) flags |= PacketFlags::IS_COMPRESSED;
    buffer.push_back(flags);
    
    // Payload length (2 bytes, big-endian) - includes original size if compressed
    uint16_t payloadLength = payload.size();
    if (isCompressed) {
        payloadLength += 2; // Add space for original size
    }
    writeUint16BigEndian(buffer, payloadLength);
    
    // Sender ID (8 bytes)
    buffer.insert(buffer.end(), packet.senderID.begin(), packet.senderID.end());
    
    // Recipient ID (if present)
    if (hasRecipient) {
        buffer.insert(buffer.end(), packet.recipientID.begin(), packet.recipientID.end());
    }
    
    // Payload (with original size if compressed)
    if (isCompressed) {
        writeUint16BigEndian(buffer, originalPayloadSize);
    }
    buffer.insert(buffer.end(), payload.begin(), payload.end());
    
    // Signature (if present)
    if (hasSignature) {
        buffer.insert(buffer.end(), packet.signature.begin(), packet.signature.end());
    }
    
    return buffer;
}

std::unique_ptr<BitchatPacket> BinaryProtocol::decodeCore(const std::vector<uint8_t>& data) {
    if (data.size() < HEADER_SIZE + SENDER_ID_SIZE) {
        ESP_LOGW(TAG, "Packet too small: %d bytes", data.size());
        return nullptr;
    }
    
    size_t offset = 0;
    
    // Parse header (matching BitChat exactly)
    uint8_t version = data[offset++];
    if (version != 1) {
        ESP_LOGW(TAG, "Unsupported version: %d", version);
        return nullptr;
    }
    
    MessageType type = static_cast<MessageType>(data[offset++]);
    uint8_t ttl = data[offset++];
    
    // Timestamp
    uint64_t timestamp = readUint64BigEndian(&data[offset]);
    offset += 8;
    
    // Flags
    uint8_t flags = data[offset++];
    bool hasRecipient = (flags & PacketFlags::HAS_RECIPIENT) != 0;
    bool hasSignature = (flags & PacketFlags::HAS_SIGNATURE) != 0;
    bool isCompressed = (flags & PacketFlags::IS_COMPRESSED) != 0;
    
    // Payload length
    uint16_t payloadLength = readUint16BigEndian(&data[offset]);
    offset += 2;
    
    // Calculate expected total size
    size_t expectedSize = HEADER_SIZE + SENDER_ID_SIZE + payloadLength;
    if (hasRecipient) expectedSize += RECIPIENT_ID_SIZE;
    if (hasSignature) expectedSize += SIGNATURE_SIZE;
    
    if (data.size() < expectedSize) {
        ESP_LOGW(TAG, "Packet size mismatch: got %d, expected %d", data.size(), expectedSize);
        return nullptr;
    }
    
    // Sender ID
    std::array<uint8_t, 8> senderID;
    std::copy(&data[offset], &data[offset + 8], senderID.begin());
    offset += 8;
    
    // Recipient ID
    std::array<uint8_t, 8> recipientID = SpecialRecipients::BROADCAST;
    if (hasRecipient) {
        std::copy(&data[offset], &data[offset + 8], recipientID.begin());
        offset += 8;
    }
    
    // Payload (with proper LZ4 decompression)
    std::vector<uint8_t> payload;
    if (isCompressed) {
        if (payloadLength < 2) {
            ESP_LOGW(TAG, "Invalid compressed payload length: %d", payloadLength);
            return nullptr;
        }
        
        uint16_t originalSize = readUint16BigEndian(&data[offset]);
        offset += 2;
        
        std::vector<uint8_t> compressedPayload(&data[offset], &data[offset + payloadLength - 2]);
        payload = CompressionUtil::decompress(compressedPayload, originalSize);
        if (payload.empty()) {
            ESP_LOGW(TAG, "Failed to decompress payload");
            return nullptr;
        }
        offset += payloadLength - 2;
        
        ESP_LOGV(TAG, "Decompressed payload from %d to %d bytes", 
                compressedPayload.size(), payload.size());
    } else {
        payload.assign(&data[offset], &data[offset + payloadLength]);
        offset += payloadLength;
    }
    
    // Signature
    std::vector<uint8_t> signature;
    if (hasSignature) {
        signature.assign(&data[offset], &data[offset + SIGNATURE_SIZE]);
    }
    
    // Create packet
    auto packet = std::make_unique<BitchatPacket>();
    packet->version = version;
    packet->type = type;
    packet->ttl = ttl;
    packet->timestamp = timestamp;
    packet->senderID = senderID;
    packet->recipientID = recipientID;
    packet->payload = payload;
    packet->signature = signature;
    packet->hasRecipient = hasRecipient;
    packet->hasSignature = hasSignature;
    packet->isCompressed = isCompressed;
    
    return packet;
}

void BinaryProtocol::writeUint16BigEndian(std::vector<uint8_t>& buffer, uint16_t value) {
    buffer.push_back((value >> 8) & 0xFF);
    buffer.push_back(value & 0xFF);
}

void BinaryProtocol::writeUint64BigEndian(std::vector<uint8_t>& buffer, uint64_t value) {
    for (int i = 7; i >= 0; i--) {
        buffer.push_back((value >> (i * 8)) & 0xFF);
    }
}

uint16_t BinaryProtocol::readUint16BigEndian(const uint8_t* data) {
    return (static_cast<uint16_t>(data[0]) << 8) | static_cast<uint16_t>(data[1]);
}

uint64_t BinaryProtocol::readUint64BigEndian(const uint8_t* data) {
    uint64_t result = 0;
    for (int i = 0; i < 8; i++) {
        result = (result << 8) | static_cast<uint64_t>(data[i]);
    }
    return result;
}

// TLVEncoding Implementation (unchanged - already correct)
std::vector<uint8_t> TLVEncoding::encode(const std::vector<TLVEntry>& entries) {
    std::vector<uint8_t> buffer;
    
    for (const auto& entry : entries) {
        encodeEntry(buffer, entry);
    }
    
    return buffer;
}

std::vector<TLVEncoding::TLVEntry> TLVEncoding::decode(const std::vector<uint8_t>& data) {
    std::vector<TLVEntry> entries;
    
    const uint8_t* ptr = data.data();
    size_t remaining = data.size();
    
    while (remaining > 0) {
        TLVEntry entry(TLVType::NICKNAME, std::vector<uint8_t>());
        
        if (!decodeEntry(ptr, remaining, entry)) {
            break;
        }
        
        entries.push_back(entry);
    }
    
    return entries;
}

const TLVEncoding::TLVEntry* TLVEncoding::findEntry(const std::vector<TLVEntry>& entries, TLVType type) {
    auto it = std::find_if(entries.begin(), entries.end(),
                          [type](const TLVEntry& entry) { return entry.type == type; });
    return (it != entries.end()) ? &(*it) : nullptr;
}

std::string TLVEncoding::extractString(const TLVEntry& entry) {
    return std::string(entry.value.begin(), entry.value.end());
}

uint8_t TLVEncoding::extractUint8(const TLVEntry& entry) {
    return entry.value.empty() ? 0 : entry.value[0];
}

uint16_t TLVEncoding::extractUint16(const TLVEntry& entry) {
    if (entry.value.size() < 2) return 0;
    return (static_cast<uint16_t>(entry.value[0]) << 8) | static_cast<uint16_t>(entry.value[1]);
}

uint32_t TLVEncoding::extractUint32(const TLVEntry& entry) {
    if (entry.value.size() < 4) return 0;
    return (static_cast<uint32_t>(entry.value[0]) << 24) |
           (static_cast<uint32_t>(entry.value[1]) << 16) |
           (static_cast<uint32_t>(entry.value[2]) << 8) |
           static_cast<uint32_t>(entry.value[3]);
}

uint64_t TLVEncoding::extractUint64(const TLVEntry& entry) {
    if (entry.value.size() < 8) return 0;
    uint64_t result = 0;
    for (int i = 0; i < 8; i++) {
        result = (result << 8) | static_cast<uint64_t>(entry.value[i]);
    }
    return result;
}

std::array<uint8_t, 32> TLVEncoding::extractByteArray32(const TLVEntry& entry) {
    std::array<uint8_t, 32> result = {};
    if (entry.value.size() >= 32) {
        std::copy(entry.value.begin(), entry.value.begin() + 32, result.begin());
    }
    return result;
}

std::vector<uint8_t> TLVEncoding::createIdentityAnnouncement(
    const std::string& nickname,
    const std::array<uint8_t, 32>& noisePublicKey,
    const std::array<uint8_t, 32>& signingPublicKey) {
    
    std::vector<TLVEntry> entries;
    entries.emplace_back(TLVType::NICKNAME, nickname);
    entries.emplace_back(TLVType::NOISE_PUBLIC_KEY, noisePublicKey);
    entries.emplace_back(TLVType::SIGNING_PUBLIC_KEY, signingPublicKey);
    
    return encode(entries);
}

bool TLVEncoding::parseIdentityAnnouncement(
    const std::vector<uint8_t>& payload,
    std::string& nickname,
    std::array<uint8_t, 32>& noisePublicKey,
    std::array<uint8_t, 32>& signingPublicKey) {
    
    auto entries = decode(payload);
    
    const TLVEntry* nicknameEntry = findEntry(entries, TLVType::NICKNAME);
    const TLVEntry* noiseKeyEntry = findEntry(entries, TLVType::NOISE_PUBLIC_KEY);
    const TLVEntry* signingKeyEntry = findEntry(entries, TLVType::SIGNING_PUBLIC_KEY);
    
    if (!nicknameEntry || !noiseKeyEntry || !signingKeyEntry) {
        return false;
    }
    
    nickname = extractString(*nicknameEntry);
    noisePublicKey = extractByteArray32(*noiseKeyEntry);
    signingPublicKey = extractByteArray32(*signingKeyEntry);
    
    return true;
}

void TLVEncoding::encodeEntry(std::vector<uint8_t>& buffer, const TLVEntry& entry) {
    buffer.push_back(static_cast<uint8_t>(entry.type));
    
    if (entry.value.size() < 255) {
        buffer.push_back(static_cast<uint8_t>(entry.value.size()));
    } else {
        buffer.push_back(255);
        buffer.push_back((entry.value.size() >> 8) & 0xFF);
        buffer.push_back(entry.value.size() & 0xFF);
    }
    
    buffer.insert(buffer.end(), entry.value.begin(), entry.value.end());
}

bool TLVEncoding::decodeEntry(const uint8_t*& data, size_t& remaining, TLVEntry& entry) {
    if (remaining < 2) {
        return false;
    }
    
    entry.type = static_cast<TLVType>(data[0]);
    uint8_t lengthField = data[1];
    data += 2;
    remaining -= 2;
    
    size_t valueLength;
    if (lengthField < 255) {
        valueLength = lengthField;
    } else {
        if (remaining < 2) {
            return false;
        }
        valueLength = (static_cast<size_t>(data[0]) << 8) | static_cast<size_t>(data[1]);
        data += 2;
        remaining -= 2;
    }
    
    if (remaining < valueLength) {
        return false;
    }
    
    entry.value.assign(data, data + valueLength);
    data += valueLength;
    remaining -= valueLength;
    
    return true;
}

// TLVEntry constructors (unchanged)
TLVEncoding::TLVEntry::TLVEntry(TLVType t, const std::string& s) : type(t) {
    value.assign(s.begin(), s.end());
}

TLVEncoding::TLVEntry::TLVEntry(TLVType t, uint8_t val) : type(t) {
    value.push_back(val);
}

TLVEncoding::TLVEntry::TLVEntry(TLVType t, uint16_t val) : type(t) {
    value.push_back((val >> 8) & 0xFF);
    value.push_back(val & 0xFF);
}

TLVEncoding::TLVEntry::TLVEntry(TLVType t, uint32_t val) : type(t) {
    value.push_back((val >> 24) & 0xFF);
    value.push_back((val >> 16) & 0xFF);
    value.push_back((val >> 8) & 0xFF);
    value.push_back(val & 0xFF);
}

TLVEncoding::TLVEntry::TLVEntry(TLVType t, uint64_t val) : type(t) {
    for (int i = 7; i >= 0; i--) {
        value.push_back((val >> (i * 8)) & 0xFF);
    }
}

TLVEncoding::TLVEntry::TLVEntry(TLVType t, const std::array<uint8_t, 32>& arr) : type(t) {
    value.assign(arr.begin(), arr.end());
}

// CompressionUtil Implementation with proper LZ4
bool CompressionUtil::shouldCompress(const std::vector<uint8_t>& data) {
    // Use BitChat's compression threshold
    return data.size() >= COMPRESSION_THRESHOLD;
}

std::vector<uint8_t> CompressionUtil::compress(const std::vector<uint8_t>& data) {
    if (data.empty()) {
        return data;
    }
    
    // Use proper LZ4 compression
    int maxCompressedSize = LZ4_compressBound(data.size());
    std::vector<uint8_t> compressed(maxCompressedSize);
    
    int compressedSize = LZ4_compress_default(
        reinterpret_cast<const char*>(data.data()),
        reinterpret_cast<char*>(compressed.data()),
        data.size(),
        maxCompressedSize
    );
    
    if (compressedSize <= 0) {
        ESP_LOGW(TAG, "LZ4 compression failed");
        return {}; // Return empty on failure
    }
    
    compressed.resize(compressedSize);
    
    // Only return compressed data if it's actually smaller
    if (compressed.size() < data.size()) {
        ESP_LOGV(TAG, "LZ4 compressed %d bytes to %d bytes (%.1f%%)", 
                data.size(), compressed.size(), 
                100.0 * compressed.size() / data.size());
        return compressed;
    }
    
    return {}; // Return empty if compression didn't help
}

std::vector<uint8_t> CompressionUtil::decompress(const std::vector<uint8_t>& compressed, size_t originalSize) {
    if (compressed.empty() || originalSize == 0) {
        return {};
    }
    
    // Use proper LZ4 decompression
    std::vector<uint8_t> decompressed(originalSize);
    
    int decompressedSize = LZ4_decompress_safe(
        reinterpret_cast<const char*>(compressed.data()),
        reinterpret_cast<char*>(decompressed.data()),
        compressed.size(),
        originalSize
    );
    
    if (decompressedSize != static_cast<int>(originalSize)) {
        ESP_LOGW(TAG, "LZ4 decompression failed or size mismatch: expected %d, got %d", 
                originalSize, decompressedSize);
        return {};
    }
    
    ESP_LOGV(TAG, "LZ4 decompressed %d bytes to %d bytes", compressed.size(), originalSize);
    return decompressed;
}

// MessagePadding Implementation (unchanged - already correct)
const std::array<size_t, 12> MessagePadding::BLOCK_SIZES = {
    32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536
};

size_t MessagePadding::optimalBlockSize(size_t originalSize) {
    for (size_t blockSize : BLOCK_SIZES) {
        if (originalSize <= blockSize) {
            return blockSize;
        }
    }
    return originalSize; // No padding if too large
}

std::vector<uint8_t> MessagePadding::pad(const std::vector<uint8_t>& data, size_t targetSize) {
    if (targetSize <= data.size()) {
        return data;
    }
    
    std::vector<uint8_t> padded = data;
    size_t paddingNeeded = targetSize - data.size();
    
    for (size_t i = 0; i < paddingNeeded; i++) {
        padded.push_back(getPaddingByte(data.size() + i));
    }
    
    return padded;
}

std::vector<uint8_t> MessagePadding::unpad(const std::vector<uint8_t>& paddedData) {
    // Find the actual data by looking for consistent padding pattern
    size_t actualSize = paddedData.size();
    
    // Simple approach: scan backwards for non-padding bytes
    for (size_t i = paddedData.size(); i > 32; i--) {
        if (paddedData[i-1] != getPaddingByte(i-1)) {
            actualSize = i;
            break;
        }
    }
    
    return std::vector<uint8_t>(paddedData.begin(), paddedData.begin() + actualSize);
}

uint8_t MessagePadding::getPaddingByte(size_t index) {
    // Generate pseudo-random but deterministic padding
    return static_cast<uint8_t>((index * 37 + 17) & 0xFF);
}

} // namespace bitchat

#endif // ENABLE_BITCHAT_MESH