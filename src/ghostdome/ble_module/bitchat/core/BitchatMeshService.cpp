#ifdef ENABLE_BITCHAT_MESH

#include "BitchatMeshService.h"
#include "ghostdome/ble_module/bitchat/models/BitchatPacket.h"
#include "ghostdome/ble_module/bitchat/protocol/BinaryProtocol.h"
#include "ghostdome/ble_module/bitchat/crypto/NoiseProtocol.h"
#include "ghostdome/ble_module/bitchat/mesh/MeshComponents.h"
#include "ghostdome/ble_module/bitchat/transport/BluetoothManager.h"
#include "ghostdome/ble_module/bitchat/identity/IdentityManager.h"

#include <esp_log.h>
#include <esp_timer.h>
#include <sstream>
#include <algorithm>
#include <memory>

static const char* TAG = "BitchatMesh";

namespace bitchat {

BitchatMeshService::BitchatMeshService()
    : isActive(false), messagesSent(0), messagesReceived(0), messagesRelayed(0) {

    ESP_LOGI(TAG, "BitChat Mesh Service created");
    
    initializeComponents();
    setupCallbacks();
}

BitchatMeshService::~BitchatMeshService() {
    stopMesh();
}

void BitchatMeshService::initializeComponents() {
    ESP_LOGI(TAG, "Initializing BitChat mesh components");
    
    // Initialize IdentityManager first (other components depend on it)
    identityManager.reset(new IdentityManager());
    
    // Create other components
    protocol.reset(new BinaryProtocol());
    peerManager.reset(new PeerManager());
    messageRouter.reset(new MessageRouter());
    noiseProtocol.reset(new NoiseProtocol(identityManager.get()));
    bluetoothManager.reset(new BluetoothManager());
    fragmentManager.reset(new FragmentManager());
    storeForward.reset(new StoreForward());
}

void BitchatMeshService::setupCallbacks() {
    // Bluetooth manager callbacks
    bluetoothManager->setPacketCallback([this](const BitchatPacket& packet, const std::string& deviceAddress) {
        handleIncomingPacket(packet, deviceAddress);
    });
    
    bluetoothManager->setConnectionCallback([this](const std::string& deviceAddress, bool connected) {
        if (connected) {
            ESP_LOGD(TAG, "Device connected: %s", deviceAddress.c_str());
        } else {
            ESP_LOGD(TAG, "Device disconnected: %s", deviceAddress.c_str());
        }
        
        if (connectionCallback) {
            connectionCallback(deviceAddress, connected);
        }
    });

    // Store-and-forward delivery callback
    storeForward->setDeliveryCallback([this](const BitchatPacket& packet) -> bool {
        return bluetoothManager->broadcastPacket(packet);
    });
}

bool BitchatMeshService::startMesh(const std::string& deviceName) {
    if (isActive) {
        ESP_LOGW(TAG, "Mesh already running");
        return true;
    }

    ESP_LOGI(TAG, "Starting BitChat mesh service: %s", deviceName.c_str());

    // Initialize IdentityManager first
    if (!identityManager->initialize()) {
        ESP_LOGE(TAG, "Failed to initialize IdentityManager");
        return false;
    }

    // Set default nickname from identity
    if (currentNickname.empty()) {
        currentNickname = "GhostDome-" + identityManager->getPeerID().substr(0, 6);
    }

    // Initialize Bluetooth manager
    if (!bluetoothManager->initialize(deviceName)) {
        ESP_LOGE(TAG, "Failed to initialize Bluetooth manager");
        return false;
    }

    // Generate static keys for Noise protocol (now uses IdentityManager keys)
    if (!noiseProtocol->generateStaticKeys()) {
        ESP_LOGE(TAG, "Failed to generate Noise static keys");
        return false;
    }

    // Start Bluetooth services
    if (!bluetoothManager->startServices()) {
        ESP_LOGE(TAG, "Failed to start Bluetooth services");
        return false;
    }

    isActive = true;

    // Send initial announcement after short delay
    xTaskCreatePinnedToCore([](void* param) {
        vTaskDelay(pdMS_TO_TICKS(1000)); // 1 second delay
        static_cast<BitchatMeshService*>(param)->sendAnnouncement();
        vTaskDelete(NULL);
    }, "InitialAnnounce", 2048, this, 1, NULL, 1);

    // Start periodic maintenance task
    xTaskCreatePinnedToCore([](void* param) {
        BitchatMeshService* service = static_cast<BitchatMeshService*>(param);
        while (service->isActive) {
            vTaskDelay(pdMS_TO_TICKS(30000)); // 30 seconds
            if (service->isActive) {
                service->sendAnnouncement();
                service->peerManager->cleanupInactivePeers();
                service->messageRouter->cleanupOldMessages();
                service->fragmentManager->cleanupExpiredFragments();
                service->storeForward->cleanupExpiredMessages();
                service->noiseProtocol->cleanupExpiredSessions();
            }
        }
        vTaskDelete(NULL);
    }, "MeshMaintenance", 4096, this, 1, NULL, 1);

    ESP_LOGI(TAG, "✅ BitChat mesh service started successfully");
    return true;
}

void BitchatMeshService::stopMesh() {
    if (!isActive) {
        return;
    }

    ESP_LOGI(TAG, "Stopping BitChat mesh service");
    
    // Send leave announcement
    auto leavePacket = BinaryProtocol::createLeave(
        utils::fromHexStringToPeerID(identityManager->getPeerID()),
        currentNickname
    );
    bluetoothManager->broadcastPacket(leavePacket);
    
    // Small delay to ensure leave message is sent
    vTaskDelay(pdMS_TO_TICKS(200));

    isActive = false;
    bluetoothManager->stopServices();
    
    ESP_LOGI(TAG, "BitChat mesh service stopped");
}

void BitchatMeshService::setNickname(const std::string& nickname) {
    if (nickname.length() > 32) {
        ESP_LOGW(TAG, "Nickname too long, truncating to 32 characters");
        currentNickname = nickname.substr(0, 32);
    } else {
        currentNickname = nickname;
    }

    ESP_LOGI(TAG, "Nickname set to: %s", currentNickname.c_str());
    
    // Send announcement with new nickname if mesh is active
    if (isActive) {
        sendAnnouncement();
    }
}

std::string BitchatMeshService::getMyPeerID() const {
    return identityManager->getPeerID();
}

std::string BitchatMeshService::getIdentityFingerprint() const {
    return identityManager->getIdentityFingerprint();
}

bool BitchatMeshService::sendBroadcastMessage(const std::string& message) {
    if (!isActive || message.empty()) {
        return false;
    }

    auto packet = BinaryProtocol::createTextMessage(
        utils::fromHexStringToPeerID(identityManager->getPeerID()),
        message
    );
    
    if (bluetoothManager->broadcastPacket(packet)) {
        messagesSent++;
        messageRouter->recordMessage(packet);
        ESP_LOGD(TAG, "Broadcast message sent: %s", message.substr(0, 50).c_str());
        return true;
    }

    return false;
}

bool BitchatMeshService::sendPrivateMessage(const std::string& message, const std::string& targetPeerID) {
    if (!isActive || message.empty() || targetPeerID.empty()) {
        return false;
    }

    // Check if we have an encrypted session with the target
    if (!noiseProtocol->hasEstablishedSession(targetPeerID)) {
        ESP_LOGD(TAG, "No encrypted session with %s, initiating handshake", targetPeerID.c_str());
        initiateEncryption(targetPeerID);
        
        // Cache message for delivery after handshake
        auto packet = BinaryProtocol::createTextMessage(
            utils::fromHexStringToPeerID(identityManager->getPeerID()),
            message,
            utils::fromHexStringToPeerID(targetPeerID)
        );
        storeForward->cacheMessage(packet, targetPeerID);
        return true;
    }

    // Create private message payload with NoisePayloadType
    NoisePayload privatePayload(NoisePayloadType::PRIVATE_MESSAGE,
                               std::vector<uint8_t>(message.begin(), message.end()));

    // Encrypt the payload
    auto encryptedData = noiseProtocol->encrypt(privatePayload.encode(), targetPeerID);
    if (encryptedData.empty()) {
        ESP_LOGE(TAG, "Failed to encrypt private message for %s", targetPeerID.c_str());
        return false;
    }

    // Create encrypted packet
    auto packet = BinaryProtocol::createNoiseEncrypted(
        utils::fromHexStringToPeerID(identityManager->getPeerID()),
        utils::fromHexStringToPeerID(targetPeerID),
        encryptedData
    );

    if (bluetoothManager->broadcastPacket(packet)) {
        messagesSent++;
        messageRouter->recordMessage(packet);
        ESP_LOGD(TAG, "Private message sent to %s", targetPeerID.c_str());
        return true;
    }

    return false;
}

bool BitchatMeshService::joinChannel(const std::string& channel, const std::string& password) {
    if (!isActive || channel.empty()) {
        return false;
    }

    ESP_LOGI(TAG, "Joining channel: %s", channel.c_str());

    // Set channel password if provided
    if (!password.empty()) {
        if (!identityManager->setChannelPassword(channel, password)) {
            ESP_LOGE(TAG, "Failed to set password for channel: %s", channel.c_str());
            return false;
        }
    }

    ESP_LOGI(TAG, "✅ Successfully joined channel: %s", channel.c_str());
    return true;
}

bool BitchatMeshService::leaveChannel(const std::string& channel) {
    if (!isActive || channel.empty()) {
        return false;
    }

    ESP_LOGI(TAG, "Leaving channel: %s", channel.c_str());

    // Remove channel password/key
    identityManager->removeChannelPassword(channel);

    ESP_LOGI(TAG, "✅ Left channel: %s", channel.c_str());
    return true;
}

bool BitchatMeshService::sendChannelMessage(const std::string& message, const std::string& channel) {
    if (!isActive || message.empty() || channel.empty()) {
        return false;
    }

    // Check if we have a password/key for this channel
    if (!identityManager->hasChannelPassword(channel)) {
        ESP_LOGW(TAG, "No password set for channel %s, sending as public broadcast", channel.c_str());
        
        // Send as public broadcast with channel prefix
        std::string channelMessage = "#" + channel + ": " + message;
        return sendBroadcastMessage(channelMessage);
    }

    // Encrypt the message using channel password
    auto encryptedData = identityManager->encryptChannelMessage(channel, message);
    if (encryptedData.empty()) {
        ESP_LOGE(TAG, "Failed to encrypt message for channel: %s", channel.c_str());
        return false;
    }

    // Create channel message packet with special channel format
    std::string channelPayload = "#" + channel + ":ENC:" + utils::toHexString(encryptedData);
    
    auto packet = BinaryProtocol::createTextMessage(
        utils::fromHexStringToPeerID(identityManager->getPeerID()),
        channelPayload
    );

    if (bluetoothManager->broadcastPacket(packet)) {
        messagesSent++;
        messageRouter->recordMessage(packet);
        ESP_LOGD(TAG, "Encrypted channel message sent to %s", channel.c_str());
        return true;
    }

    return false;
}

std::vector<std::string> BitchatMeshService::getJoinedChannels() const {
    return identityManager->getJoinedChannels();
}

bool BitchatMeshService::setChannelPassword(const std::string& channel, const std::string& password) {
    if (!isActive) {
        return false;
    }
    
    return identityManager->setChannelPassword(channel, password);
}

bool BitchatMeshService::hasChannelPassword(const std::string& channel) const {
    return identityManager->hasChannelPassword(channel);
}

bool BitchatMeshService::processCommand(const std::string& command) {
    if (!isActive || command.empty() || command[0] != '/') {
        return false;
    }

    auto args = parseCommand(command);
    if (args.empty()) {
        return false;
    }

    std::string cmd = args[0];
    std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::tolower);

    ESP_LOGD(TAG, "Processing command: %s", cmd.c_str());

    // IRC-style commands matching BitChat Android
    if (cmd == "/join" || cmd == "/j") {
        return processJoinCommand(args);
    } else if (cmd == "/leave" || cmd == "/part") {
        return processLeaveCommand(args);
    } else if (cmd == "/msg" || cmd == "/m") {
        return processMessageCommand(args);
    } else if (cmd == "/who") {
        return processWhoCommand(args);
    } else if (cmd == "/block") {
        return processBlockCommand(args);
    } else if (cmd == "/pass") {
        return processPassCommand(args);
    } else if (cmd == "/help") {
        ESP_LOGI(TAG, "BitChat Commands:\n%s", getCommandHelp().c_str());
        return true;
    }

    ESP_LOGW(TAG, "Unknown command: %s", cmd.c_str());
    return false;
}

std::string BitchatMeshService::getCommandHelp() const {
    return R"(BitChat IRC-style Commands:
/join #channel [password] - Join a channel
/j #channel [password]    - Join a channel (short)
/leave #channel           - Leave a channel  
/part #channel            - Leave a channel (IRC style)
/msg @user message        - Send private message
/m @user message          - Send private message (short)
/who                      - List active peers
/block @user              - Block a user
/pass password            - Set channel password
/help                     - Show this help)";
}

std::vector<std::string> BitchatMeshService::getActivePeers() const {
    return peerManager->getActivePeerIDs();
}

std::vector<PeerInfo> BitchatMeshService::getPeerInfo() const {
    return peerManager->getAllPeers();
}

bool BitchatMeshService::hasEncryptedSession(const std::string& peerID) const {
    return noiseProtocol->hasEstablishedSession(peerID);
}

void BitchatMeshService::initiateEncryption(const std::string& peerID) {
    if (!isActive) {
        return;
    }

    ESP_LOGD(TAG, "Initiating encryption handshake with %s", peerID.c_str());
    
    if (noiseProtocol->initiateHandshake(peerID)) {
        auto handshakeData = noiseProtocol->getHandshakeMessage(peerID);
        if (!handshakeData.empty()) {
            auto packet = BinaryProtocol::createNoiseHandshake(
                utils::fromHexStringToPeerID(identityManager->getPeerID()),
                utils::fromHexStringToPeerID(peerID),
                handshakeData
            );
            bluetoothManager->broadcastPacket(packet);
        }
    }
}

void BitchatMeshService::sendReadReceipt(const std::string& messageID, const std::string& toPeerID) {
    if (!isActive || !noiseProtocol->hasEstablishedSession(toPeerID)) {
        return;
    }

    // Create read receipt payload
    NoisePayload receiptPayload(NoisePayloadType::READ_RECEIPT,
                               std::vector<uint8_t>(messageID.begin(), messageID.end()));

    // Encrypt the payload
    auto encryptedData = noiseProtocol->encrypt(receiptPayload.encode(), toPeerID);
    if (encryptedData.empty()) {
        return;
    }

    // Send as encrypted packet
    auto packet = BinaryProtocol::createNoiseEncrypted(
        utils::fromHexStringToPeerID(identityManager->getPeerID()),
        utils::fromHexStringToPeerID(toPeerID),
        encryptedData
    );

    bluetoothManager->broadcastPacket(packet);
}

BitchatMeshService::MeshStatus BitchatMeshService::getStatus() const {
    MeshStatus status;
    status.isActive = isActive;
    status.messagesSent = messagesSent;
    status.messagesReceived = messagesReceived;
    status.messagesRelayed = messagesRelayed;
    status.activePeers = peerManager->getActivePeerCount();
    status.encryptedSessions = noiseProtocol->getActiveSessions().size();
    status.myPeerID = identityManager->getPeerID();
    status.myFingerprint = getIdentityFingerprint();
    status.joinedChannels = getJoinedChannels();
    status.identityManagerReady = identityManager->isInitialized();
    return status;
}

std::string BitchatMeshService::getDebugInfo() const {
    std::stringstream ss;
    ss << "=== BitChat Mesh Service Debug ===\n";
    ss << "Peer ID: " << identityManager->getPeerID() << "\n";
    ss << "Nickname: " << currentNickname << "\n";
    ss << "Active: " << (isActive ? "YES" : "NO") << "\n";
    ss << "Messages Sent: " << messagesSent << "\n";
    ss << "Messages Received: " << messagesReceived << "\n";
    ss << "Messages Relayed: " << messagesRelayed << "\n";
    ss << "Active Peers: " << peerManager->getActivePeerCount() << "\n";
    ss << "Encrypted Sessions: " << noiseProtocol->getActiveSessions().size() << "\n";
    ss << "Joined Channels: " << getJoinedChannels().size() << "\n";
    
    if (identityManager->isInitialized()) {
        ss << "\n" << identityManager->getDebugInfo();
    }
    
    ss << "\n" << peerManager->getDebugInfo();
    ss << "\n" << messageRouter->getDebugInfo();
    ss << "\n" << bluetoothManager->getDebugInfo();
    
    return ss.str();
}

void BitchatMeshService::emergencyWipe() {
    ESP_LOGW(TAG, "🚨 Emergency wipe initiated! 🚨");
    
    // Clear all mesh data
    peerManager->clearAllPeers();
    messageRouter->clearAllMessages();
    fragmentManager->clearAllFragments();
    storeForward->clearAllCachedMessages();
    noiseProtocol->clearAllSessions();
    
    // Wipe identity manager (keys, channels, etc.)
    identityManager->emergencyWipe();
    
    ESP_LOGW(TAG, "🚨 Emergency wipe completed 🚨");
}

bool BitchatMeshService::rotateIdentity() {
    if (!isActive) {
        return false;
    }
    
    ESP_LOGI(TAG, "Rotating mesh identity");
    
    // Rotate both Noise and signing keys
    bool success = identityManager->rotateNoiseKeys() && identityManager->rotateSigningKeys();
    
    if (success) {
        // Regenerate keys in NoiseProtocol
        noiseProtocol->generateStaticKeys();
        
        // Send new announcement with rotated identity
        sendAnnouncement();
        
        ESP_LOGI(TAG, "✅ Identity rotation completed");
    } else {
        ESP_LOGE(TAG, "❌ Identity rotation failed");
    }
    
    return success;
}

// Private methods implementation
void BitchatMeshService::handleIncomingPacket(const BitchatPacket& packet, const std::string& fromDeviceAddress) {
    messagesReceived++;

    // Check if we've seen this message before
    if (messageRouter->isMessageSeen(packet)) {
        ESP_LOGV(TAG, "Duplicate message from %s, ignoring", packet.getSenderIDString().c_str());
        return;
    }

    // Record the message
    messageRouter->recordMessage(packet);

    // Update peer last seen
    std::string senderID = packet.getSenderIDString();
    peerManager->updatePeerLastSeen(senderID);

    // Handle based on message type
    switch (packet.type) {
        case MessageType::ANNOUNCE:
            handlePeerAnnouncement(packet);
            break;
        case MessageType::MESSAGE:
            handleTextMessage(packet);
            break;
        case MessageType::NOISE_HANDSHAKE:
            handleNoiseHandshake(packet);
            break;
        case MessageType::NOISE_ENCRYPTED:
            handleEncryptedMessage(packet);
            break;
        case MessageType::FRAGMENT:
            handleFragmentedMessage(packet);
            break;
        case MessageType::LEAVE:
            handleLeaveMessage(packet);
            break;
        default:
            ESP_LOGW(TAG, "Unknown message type: %d", static_cast<int>(packet.type));
            break;
    }

    // Consider relaying the message
    if (messageRouter->shouldRelay(packet, peerManager->getActivePeerCount()) && packet.ttl > 1) {
        BitchatPacket relayPacket = packet;
        relayPacket.ttl--;
        
        if (bluetoothManager->broadcastPacket(relayPacket)) {
            messagesRelayed++;
            messageRouter->recordRelay(relayPacket);
            ESP_LOGV(TAG, "Relayed message from %s, TTL: %d", senderID.c_str(), relayPacket.ttl);
        }
    }

    // Notify application layer
    updatePeerList();
}

void BitchatMeshService::handlePeerAnnouncement(const BitchatPacket& packet) {
    std::string senderID = packet.getSenderIDString();

    // Parse TLV-encoded announcement
    auto tlvEntries = TLVEncoding::decode(packet.payload);
    std::string nickname;
    std::array<uint8_t, 32> noisePublicKey = {};
    std::array<uint8_t, 32> signingPublicKey = {};

    if (TLVEncoding::parseIdentityAnnouncement(packet.payload, nickname, noisePublicKey, signingPublicKey)) {
        // Add or update peer
        if (peerManager->addPeer(senderID, nickname)) {
            peerManager->updatePeerKeys(senderID, noisePublicKey, signingPublicKey);
            ESP_LOGI(TAG, "Peer announced: %s (%s)", nickname.c_str(), senderID.c_str());
            
            // Check if we have cached messages for this peer
            storeForward->deliverCachedMessages(senderID);
        }
    } else {
        ESP_LOGW(TAG, "Failed to parse peer announcement from %s", senderID.c_str());
    }
}

void BitchatMeshService::handleTextMessage(const BitchatPacket& packet) {
    std::string senderID = packet.getSenderIDString();
    std::string message(packet.payload.begin(), packet.payload.end());

    // Check if this is a channel message
    std::string channelName;
    std::string actualMessage;
    
    if (isChannelMessage(message, channelName, actualMessage)) {
        handleChannelMessage(packet);
        return;
    }

    // Check if message is for us or broadcast
    bool isForUs = packet.isBroadcast() || packet.isDirectedTo(utils::fromHexStringToPeerID(identityManager->getPeerID()));

    if (isForUs && messageCallback) {
        messageCallback(message, senderID, !packet.isBroadcast());
    }

    ESP_LOGD(TAG, "Text message from %s: %s", senderID.c_str(), message.substr(0, 50).c_str());
}

void BitchatMeshService::handleChannelMessage(const BitchatPacket& packet) {
    std::string senderID = packet.getSenderIDString();
    std::string message(packet.payload.begin(), packet.payload.end());

    std::string channelName;
    std::string actualMessage;
    
    if (!isChannelMessage(message, channelName, actualMessage)) {
        return;
    }

    ESP_LOGD(TAG, "Channel message from %s to #%s", senderID.c_str(), channelName.c_str());

    // Check if this is an encrypted channel message
    if (actualMessage.find("ENC:") == 0) {
        // Remove "ENC:" prefix and get hex data
        std::string hexData = actualMessage.substr(4);
        
        // Convert hex to bytes
        std::vector<uint8_t> encryptedData;
        for (size_t i = 0; i < hexData.length(); i += 2) {
            if (i + 1 < hexData.length()) {
                uint8_t byte = std::stoul(hexData.substr(i, 2), nullptr, 16);
                encryptedData.push_back(byte);
            }
        }
        
        // Try to decrypt using our channel password
        if (identityManager->hasChannelPassword(channelName)) {
            std::string decryptedMessage = identityManager->decryptChannelMessage(channelName, encryptedData);
            
            if (!decryptedMessage.empty()) {
                ESP_LOGD(TAG, "Decrypted channel message: %s", decryptedMessage.c_str());
                
                if (channelMessageCallback) {
                    channelMessageCallback(decryptedMessage, senderID, channelName);
                }
            } else {
                ESP_LOGD(TAG, "Failed to decrypt channel message (wrong password?)");
            }
        } else {
            ESP_LOGD(TAG, "Received encrypted message for channel %s but no password set", channelName.c_str());
        }
    } else {
        // Plain text channel message
        if (channelMessageCallback) {
            channelMessageCallback(actualMessage, senderID, channelName);
        }
    }
}

void BitchatMeshService::handleEncryptedMessage(const BitchatPacket& packet) {
    std::string senderID = packet.getSenderIDString();

    // Only process if message is for us
    if (!packet.isDirectedTo(utils::fromHexStringToPeerID(identityManager->getPeerID()))) {
        return;
    }

    // Decrypt the payload
    auto decryptedData = noiseProtocol->decrypt(packet.payload, senderID);
    if (decryptedData.empty()) {
        ESP_LOGW(TAG, "Failed to decrypt message from %s", senderID.c_str());
        return;
    }

    // Parse NoisePayload
    auto noisePayload = NoisePayload::decode(decryptedData);
    if (!noisePayload) {
        ESP_LOGW(TAG, "Failed to parse encrypted payload from %s", senderID.c_str());
        return;
    }

    switch (noisePayload->type) {
        case NoisePayloadType::PRIVATE_MESSAGE: {
            std::string message(noisePayload->data.begin(), noisePayload->data.end());
            if (messageCallback) {
                messageCallback(message, senderID, true);
            }
            ESP_LOGD(TAG, "Private message from %s: %s", senderID.c_str(), message.substr(0, 50).c_str());
            break;
        }

        case NoisePayloadType::READ_RECEIPT: {
            std::string messageID(noisePayload->data.begin(), noisePayload->data.end());
            if (deliveryCallback) {
                deliveryCallback(messageID, senderID, true);
            }
            ESP_LOGD(TAG, "Read receipt from %s for message %s", senderID.c_str(), messageID.c_str());
            break;
        }

        default:
            ESP_LOGW(TAG, "Unknown encrypted payload type: %d", static_cast<int>(noisePayload->type));
            break;
    }
}

void BitchatMeshService::handleNoiseHandshake(const BitchatPacket& packet) {
    std::string senderID = packet.getSenderIDString();

    // Only process handshake messages directed to us
    if (!packet.isDirectedTo(utils::fromHexStringToPeerID(identityManager->getPeerID()))) {
        return;
    }

    ESP_LOGD(TAG, "Processing Noise handshake from %s", senderID.c_str());
    
    if (noiseProtocol->processHandshakeMessage(senderID, packet.payload)) {
        // Get response message if needed
        auto responseData = noiseProtocol->getHandshakeMessage(senderID);
        if (!responseData.empty()) {
            auto responsePacket = BinaryProtocol::createNoiseHandshake(
                utils::fromHexStringToPeerID(identityManager->getPeerID()),
                utils::fromHexStringToPeerID(senderID),
                responseData
            );
            bluetoothManager->broadcastPacket(responsePacket);
        }

        // Check if session is now established
        if (noiseProtocol->hasEstablishedSession(senderID)) {
            peerManager->setPeerEncryptedSession(senderID, true);
            ESP_LOGI(TAG, "✅ Noise session established with %s", senderID.c_str());
            
            // Deliver any cached messages
            storeForward->deliverCachedMessages(senderID);
        }
    }
}

void BitchatMeshService::handleFragmentedMessage(const BitchatPacket& packet) {
    auto completePacket = fragmentManager->handleFragment(packet);
    if (completePacket) {
        // Process the reassembled packet
        handleIncomingPacket(*completePacket, "");
    }
}

void BitchatMeshService::handleLeaveMessage(const BitchatPacket& packet) {
    std::string senderID = packet.getSenderIDString();
    std::string nickname(packet.payload.begin(), packet.payload.end());

    ESP_LOGI(TAG, "Peer left: %s (%s)", nickname.c_str(), senderID.c_str());
    peerManager->removePeer(senderID);
    noiseProtocol->removeSession(senderID);
    updatePeerList();
}

void BitchatMeshService::sendAnnouncement() {
    if (!isActive) {
        return;
    }

    auto packet = BinaryProtocol::createAnnouncement(
        utils::fromHexStringToPeerID(identityManager->getPeerID()),
        currentNickname,
        identityManager->getNoisePublicKey(),
        identityManager->getSigningPublicKey()
    );

    // Sign the announcement (if signing is enabled)
    if (packet.payload.size() > 0) {
        auto signature = identityManager->signAnnouncement(packet.payload);
        if (!signature.empty()) {
            packet.signature = signature;
            packet.hasSignature = true;
        }
    }

    bluetoothManager->broadcastPacket(packet);
    ESP_LOGV(TAG, "Sent announcement: %s", currentNickname.c_str());
}

void BitchatMeshService::processMessageQueue() {
    // Process any queued operations
    // This can be expanded for more sophisticated queuing
}

void BitchatMeshService::updatePeerList() {
    if (peerUpdateCallback) {
        peerUpdateCallback(getActivePeers());
    }
}

bool BitchatMeshService::isChannelMessage(const std::string& message, std::string& channelName, std::string& actualMessage) {
    if (message.length() < 2 || message[0] != '#') {
        return false;
    }

    size_t colonPos = message.find(':');
    if (colonPos == std::string::npos || colonPos <= 1) {
        return false;
    }

    channelName = message.substr(1, colonPos - 1);
    actualMessage = message.substr(colonPos + 1);

    // Trim whitespace from actual message
    actualMessage.erase(0, actualMessage.find_first_not_of(" \t"));

    return true;
}

std::string BitchatMeshService::formatChannelMessage(const std::string& channel, const std::string& message) {
    return "#" + channel + ": " + message;
}

// IRC-style command processing
bool BitchatMeshService::processJoinCommand(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        ESP_LOGW(TAG, "Usage: /join #channel [password]");
        return false;
    }

    std::string channel = args[1];
    std::string password;
    
    if (args.size() >= 3) {
        password = args[2];
    }

    // Remove # prefix if present
    if (channel[0] == '#') {
        channel = channel.substr(1);
    }

    return joinChannel(channel, password);
}

bool BitchatMeshService::processLeaveCommand(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        ESP_LOGW(TAG, "Usage: /leave #channel");
        return false;
    }

    std::string channel = args[1];
    
    // Remove # prefix if present
    if (channel[0] == '#') {
        channel = channel.substr(1);
    }

    return leaveChannel(channel);
}

bool BitchatMeshService::processMessageCommand(const std::vector<std::string>& args) {
    if (args.size() < 3) {
        ESP_LOGW(TAG, "Usage: /msg @user message");
        return false;
    }

    std::string targetUser = args[1];
    
    // Remove @ prefix if present
    if (targetUser[0] == '@') {
        targetUser = targetUser.substr(1);
    }

    // Combine remaining args as message
    std::string message;
    for (size_t i = 2; i < args.size(); i++) {
        if (i > 2) message += " ";
        message += args[i];
    }

    // Find peer ID by nickname (simplified - would need proper peer resolution)
    auto peers = getPeerInfo();
    for (const auto& peer : peers) {
        if (peer.nickname == targetUser) {
            return sendPrivateMessage(message, peer.peerID);
        }
    }

    ESP_LOGW(TAG, "User @%s not found", targetUser.c_str());
    return false;
}

bool BitchatMeshService::processWhoCommand(const std::vector<std::string>& args) {
    auto peers = getPeerInfo();
    
    ESP_LOGI(TAG, "Active Peers (%d):", peers.size());
    for (const auto& peer : peers) {
        ESP_LOGI(TAG, "  @%s (%s) - %s", 
                peer.nickname.c_str(), 
                peer.peerID.substr(0, 8).c_str(),
                peer.hasEncryptedSession ? "encrypted" : "plain");
    }
    
    return true;
}

bool BitchatMeshService::processBlockCommand(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        ESP_LOGW(TAG, "Usage: /block @user");
        return false;
    }

    std::string targetUser = args[1];
    if (targetUser[0] == '@') {
        targetUser = targetUser.substr(1);
    }

    ESP_LOGI(TAG, "Blocking user: @%s", targetUser.c_str());
    // TODO: Implement actual blocking functionality
    return true;
}

bool BitchatMeshService::processPassCommand(const std::vector<std::string>& args) {
    if (args.size() < 2) {
        ESP_LOGW(TAG, "Usage: /pass password");
        return false;
    }

    std::string password = args[1];
    
    // For now, this would set password for the current channel context
    // In a full implementation, this would depend on UI context
    ESP_LOGI(TAG, "Password command received");
    // TODO: Implement channel context awareness
    return true;
}

std::vector<std::string> BitchatMeshService::parseCommand(const std::string& command) {
    std::vector<std::string> args;
    std::stringstream ss(command);
    std::string arg;

    while (ss >> arg) {
        args.push_back(arg);
    }

    return args;
}

} // namespace bitchat

#endif // ENABLE_BITCHAT_MESH