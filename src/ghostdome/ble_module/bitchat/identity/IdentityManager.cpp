#ifdef ENABLE_BITCHAT_MESH
#include <FreeRTOS.h> // Required before task.h
#include <freertos/task.h> // Required for uxTaskGetStackHighWaterMark()
#include <esp_system.h> // Required for esp_get_free_heap_size()
#include "IdentityManager.h"
#include <esp_log.h>
#include <esp_timer.h>
#include <mbedtls/sha256.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <cstring>
#include <sstream>



static const char* TAG = "IdentityManager";

namespace bitchat {

IdentityManager::IdentityManager() 
    : initialized(false), noiseKeysGenerated(false), signingKeysGenerated(false), nvsHandle(0) {
    
    noisePrivateKey.fill(0);
    noisePublicKey.fill(0);
    signingPrivateKey.fill(0);
    signingPublicKey.fill(0);
}

IdentityManager::~IdentityManager() {
    shutdown();
}

bool IdentityManager::initialize() {
    printf("IdentityManager::initialize() - Entry point\n");
    printf("Heap: %u, Stack HWM: %u\n", esp_get_free_heap_size(), uxTaskGetStackHighWaterMark(NULL));
    std::lock_guard<std::mutex> lock(keysMutex);

    if (initialized) {
        printf("Already initialized, returning\n");
        return true;
    }

    printf("Step 1: Opening NVS storage. Heap: %u, Stack HWM: %u\n", esp_get_free_heap_size(), uxTaskGetStackHighWaterMark(NULL));

    // DON'T RE-INITIALIZE NVS - Meshtastic already did this
    // Just open our namespace directly
    esp_err_t err = nvs_open(NVS_NAMESPACE, NVS_READWRITE, &nvsHandle);
    printf("NVS open result: %d, nvsHandle: %p. Heap: %u, Stack HWM: %u\n", err, (void*)nvsHandle, esp_get_free_heap_size(), uxTaskGetStackHighWaterMark(NULL));
    
    if (err != ESP_OK) {
        printf("Error opening NVS handle: %s\n", esp_err_to_name(err));
        return false;
    }

    // Continue with the rest of your initialization...
    printf("Step 2: Loading keys from storage...\n");

    // Try to load existing keys from storage
    ESP_LOGD(TAG, "Attempting to load keys from storage... Heap: %u, Stack HWM: %u", esp_get_free_heap_size(), uxTaskGetStackHighWaterMark(NULL));
    bool keysLoaded = loadFromStorage();
    printf("Step 3: Keys loaded result: %s\n", keysLoaded ? "true" : "false");
    ESP_LOGD(TAG, "Keys loaded from storage: %s. Heap: %u, Stack HWM: %u", keysLoaded ? "true" : "false", esp_get_free_heap_size(), uxTaskGetStackHighWaterMark(NULL));

    // Generate keys if they don't exist
    if (!keysLoaded || !noiseKeysGenerated) {
          printf("Step 5: Generating noise keys...\n");
        ESP_LOGD(TAG, "Noise keys not loaded or generated, attempting to generate... Heap: %u, Stack HWM: %u", esp_get_free_heap_size(), uxTaskGetStackHighWaterMark(NULL));
        if (!generateNoiseKeys()) {
            printf("ERROR: Failed to generate Noise keys\n");
            ESP_LOGE(TAG, "Failed to generate Noise keys");
            return false;
        }
         printf("Step 6: Noise keys generated successfully\n");
        ESP_LOGD(TAG, "Noise keys generation successful. Heap: %u, Stack HWM: %u", esp_get_free_heap_size(), uxTaskGetStackHighWaterMark(NULL));
    }
     printf("Step 7: Checking signing keys...\n");
    if (!keysLoaded || !signingKeysGenerated) {
        ESP_LOGD(TAG, "Signing keys not loaded or generated, attempting to generate... Heap: %u, Stack HWM: %u", esp_get_free_heap_size(), uxTaskGetStackHighWaterMark(NULL));
        printf("Signing keys not loaded or generated, attempting to generate...\n");
        if (!generateSigningKeys()) {
            ESP_LOGE(TAG, "Failed to generate signing keys");
            printf("ERROR: Failed to generate signing keys\n");
            return false;
        }
        ESP_LOGD(TAG, "Signing keys generation successful. Heap: %u, Stack HWM: %u", esp_get_free_heap_size(), uxTaskGetStackHighWaterMark(NULL));
    }
    printf("Step 8: Ensuring Peer ID...\n");
    // Generate peer ID if not loaded
    if (myPeerID.empty()) {
        ESP_LOGD(TAG, "Peer ID empty, generating random Peer ID... Heap: %u, Stack HWM: %u", esp_get_free_heap_size(), uxTaskGetStackHighWaterMark(NULL));
        printf("Peer ID empty, generating random Peer ID...\n");
        myPeerID = utils::toHexString(utils::generateRandomPeerID());
        ESP_LOGD(TAG, "Generated Peer ID: %s. Heap: %u, Stack HWM: %u", myPeerID.c_str(), esp_get_free_heap_size(), uxTaskGetStackHighWaterMark(NULL));
        printf("Generated Peer ID: %s\n", myPeerID.c_str());
        saveToStorage(); // Save the new peer ID
        ESP_LOGD(TAG, "New Peer ID saved to storage. Heap: %u, Stack HWM: %u", esp_get_free_heap_size(), uxTaskGetStackHighWaterMark(NULL));
        printf("New Peer ID saved to storage.\n");
    }

    initialized = true;
    
    ESP_LOGI(TAG, "IdentityManager initialized successfully");
    printf("Step 9: IdentityManager initialization complete\n");
    ESP_LOGI(TAG, "Peer ID: %s", myPeerID.c_str());
    printf("Peer ID: %s\n", myPeerID.c_str());
    ESP_LOGI(TAG, "Noise Fingerprint: %s", getNoiseFingerprint().substr(0, 16).c_str());
    printf("Noise Fingerprint: %s\n", getNoiseFingerprint().substr(0, 16).c_str());
    ESP_LOGI(TAG, "Signing Fingerprint: %s", getSigningFingerprint().substr(0, 16).c_str());
    printf("Signing Fingerprint: %s\n", getSigningFingerprint().substr(0, 16).c_str());
    ESP_LOGD(TAG, "IdentityManager::initialize() - Exit. Heap: %u, Stack HWM: %u", esp_get_free_heap_size(), uxTaskGetStackHighWaterMark(NULL));
    printf("IdentityManager::initialize() - Exit. Heap: %u, Stack HWM: %u\n", esp_get_free_heap_size(), uxTaskGetStackHighWaterMark(NULL));
    return true;
}

void IdentityManager::shutdown() {
    std::lock_guard<std::mutex> lock(keysMutex);
    
    if (!initialized) {
        return;
    }
    
    // Save current state
    saveToStorage();
    
    // Close NVS handle
    if (nvsHandle != 0) {
        nvs_close(nvsHandle);
        nvsHandle = 0;
    }
    
    // Clear sensitive data
    noisePrivateKey.fill(0);
    signingPrivateKey.fill(0);
    
    for (auto& [channelName, channelKey] : channelKeys) {
        channelKey.key.fill(0);
    }
    channelKeys.clear();
    
    initialized = false;
    ESP_LOGI(TAG, "IdentityManager shutdown complete");
}
    
bool IdentityManager::generateNoiseKeys() {
    ESP_LOGI(TAG, "Generating X25519 Noise protocol keys");
    printf("Generating X25519 Noise protocol keys\n");
    // For now, use simplified key generation (replace with proper X25519 in production)
    // TODO: Replace with rweather/Crypto X25519 implementation
    if (!generateX25519KeyPair()) {
        return false;
    }
    
    noiseKeysGenerated = true;
    ESP_LOGI(TAG, "✅ X25519 Noise keys generated successfully");
    ESP_LOGW(TAG, "⚠️  Using simplified X25519 - replace with rweather/Crypto for production");
    printf("X25519 Noise keys generated successfully\n");
    printf("⚠️  Using simplified X25519 - replace with rweather/Crypto for production\n");

    return true;
}

std::array<uint8_t, 32> IdentityManager::getNoisePrivateKey() const {
    std::lock_guard<std::mutex> lock(keysMutex);
    printf("Accessing Noise private key\n");
    return noisePrivateKey;
}

std::array<uint8_t, 32> IdentityManager::getNoisePublicKey() const {
    std::lock_guard<std::mutex> lock(keysMutex);
    printf("Accessing Noise public key\n");
    return noisePublicKey;
}

std::string IdentityManager::getNoiseFingerprint() const {
    std::lock_guard<std::mutex> lock(keysMutex);
    printf("Accessing Noise fingerprint\n");
    if (!noiseKeysGenerated) {
        return "";
    }
    
    // SHA-256 hash of public key
    std::vector<uint8_t> pubKeyVec(noisePublicKey.begin(), noisePublicKey.end());
    auto hash = utils::sha256(pubKeyVec);
    return utils::toHexString(hash);

}

bool IdentityManager::generateSigningKeys() {
    ESP_LOGI(TAG, "Generating Ed25519 signing keys");
    printf("Generating Ed25519 signing keys\n");
    // For now, use simplified key generation (replace with proper Ed25519 in production)
    // TODO: Replace with rweather/Crypto Ed25519 implementation
    if (!generateEd25519KeyPair()) {
        return false;
    }
    
    signingKeysGenerated = true;
    ESP_LOGI(TAG, "✅ Ed25519 signing keys generated successfully");
    ESP_LOGW(TAG, "⚠️  Using simplified Ed25519 - replace with rweather/Crypto for production");
    
    return true;
}

std::array<uint8_t, 64> IdentityManager::getSigningPrivateKey() const {
    std::lock_guard<std::mutex> lock(keysMutex);
    printf("Accessing Ed25519 signing private key\n");
    return signingPrivateKey;
}

std::array<uint8_t, 32> IdentityManager::getSigningPublicKey() const {
    std::lock_guard<std::mutex> lock(keysMutex);
    printf("Accessing Ed25519 signing public key\n");
    return signingPublicKey;
}

std::string IdentityManager::getSigningFingerprint() const {
    std::lock_guard<std::mutex> lock(keysMutex);
    printf("Accessing Ed25519 signing fingerprint\n");
    if (!signingKeysGenerated) {
        return "";
    }
    
    // SHA-256 hash of public key
    std::vector<uint8_t> pubKeyVec(signingPublicKey.begin(), signingPublicKey.end());
    auto hash = utils::sha256(pubKeyVec);
    return utils::toHexString(hash);
}

std::string IdentityManager::getIdentityFingerprint() const {
    std::lock_guard<std::mutex> lock(keysMutex);
    printf("Accessing identity fingerprint\n");

    // Combined fingerprint: SHA-256(noise_pubkey || signing_pubkey)
    std::vector<uint8_t> combined;
    combined.insert(combined.end(), noisePublicKey.begin(), noisePublicKey.end());
    combined.insert(combined.end(), signingPublicKey.begin(), signingPublicKey.end());
    
    auto hash = utils::sha256(combined);
    return utils::toHexString(hash);
}

std::string IdentityManager::getPeerID() const {
    std::lock_guard<std::mutex> lock(keysMutex);
    printf("Accessing peer ID\n");
    return myPeerID;
}

void IdentityManager::setPeerID(const std::string& peerID) {
    std::lock_guard<std::mutex> lock(keysMutex);
    myPeerID = peerID;
    printf("Peer ID set to: %s\n", myPeerID.c_str());
    saveToStorage();
}

bool IdentityManager::setChannelPassword(const std::string& channelName, const std::string& password) {
    std::lock_guard<std::mutex> lock(keysMutex);
    
    ESP_LOGI(TAG, "Setting password for channel: %s", channelName.c_str());
    printf("Setting password for channel: %s\n", channelName.c_str());

    ChannelKey channelKey;
    channelKey.channelName = channelName;
    channelKey.createdTime = esp_timer_get_time() / 1000;
    channelKey.iterations = DEFAULT_PBKDF2_ITERATIONS;
    
    // Generate random salt
    esp_fill_random(channelKey.salt.data(), PBKDF2_SALT_SIZE);
    printf("Generated random salt for channel: %s\n", channelName.c_str());

    // Derive key from password using PBKDF2-HMAC-SHA256
    if (!deriveChannelKey(password, channelKey.salt, channelKey.iterations, channelKey.key)) {
        ESP_LOGE(TAG, "Failed to derive channel key for %s", channelName.c_str());
        return false;
    }
    
    // Store the channel key
    channelKeys[channelName] = channelKey;
    
    // Save to persistent storage
    saveToStorage();
    
    ESP_LOGI(TAG, "✅ Channel password set for: %s", channelName.c_str());
    printf("Channel password set for: %s\n", channelName.c_str());
    return true;
}

bool IdentityManager::hasChannelPassword(const std::string& channelName) const {
    std::lock_guard<std::mutex> lock(keysMutex);
    printf("Checking if channel password exists for: %s\n", channelName.c_str());
    return channelKeys.find(channelName) != channelKeys.end();
}

bool IdentityManager::removeChannelPassword(const std::string& channelName) {
    std::lock_guard<std::mutex> lock(keysMutex);
    
    auto it = channelKeys.find(channelName);
    if (it != channelKeys.end()) {
        // Clear the key data before removal
        it->second.key.fill(0);
        channelKeys.erase(it);
        saveToStorage();
        
        ESP_LOGI(TAG, "Removed channel password for: %s", channelName.c_str());
        return true;
    }
    
    return false;
}

std::vector<std::string> IdentityManager::getJoinedChannels() const {
    std::lock_guard<std::mutex> lock(keysMutex);
    
    std::vector<std::string> channels;
    for (const auto& [channelName, channelKey] : channelKeys) {
        channels.push_back(channelName);
    }
    
    return channels;
}

std::vector<uint8_t> IdentityManager::encryptChannelMessage(const std::string& channelName, const std::string& message) {
    std::lock_guard<std::mutex> lock(keysMutex);
    
    // Find channel key
    auto it = channelKeys.find(channelName);
    if (it == channelKeys.end()) {
        ESP_LOGW(TAG, "No password set for channel: %s", channelName.c_str());
        return {};
    }
    
    // Convert message to bytes
    std::vector<uint8_t> plaintext(message.begin(), message.end());
    
    // Encrypt using AES-256-GCM
    std::vector<uint8_t> ciphertext;
    if (!aesGcmEncrypt(it->second.key, plaintext, ciphertext)) {
        ESP_LOGE(TAG, "Failed to encrypt message for channel: %s", channelName.c_str());
        return {};
    }
    
    ESP_LOGV(TAG, "Encrypted message for channel %s: %d bytes -> %d bytes", 
            channelName.c_str(), plaintext.size(), ciphertext.size());
    
    return ciphertext;
}

std::string IdentityManager::decryptChannelMessage(const std::string& channelName, const std::vector<uint8_t>& encryptedData) {
    std::lock_guard<std::mutex> lock(keysMutex);
    
    // Find channel key
    auto it = channelKeys.find(channelName);
    if (it == channelKeys.end()) {
        ESP_LOGW(TAG, "No password set for channel: %s", channelName.c_str());
        return "";
    }
    
    // Decrypt using AES-256-GCM
    std::vector<uint8_t> plaintext;
    if (!aesGcmDecrypt(it->second.key, encryptedData, plaintext)) {
        ESP_LOGW(TAG, "Failed to decrypt message for channel: %s", channelName.c_str());
        return "";
    }
    
    // Convert back to string
    std::string message(plaintext.begin(), plaintext.end());
    
    ESP_LOGV(TAG, "Decrypted message for channel %s: %d bytes -> %d bytes", 
            channelName.c_str(), encryptedData.size(), plaintext.size());
    
    return message;
}

std::vector<uint8_t> IdentityManager::signAnnouncement(const std::vector<uint8_t>& announcementData) {
    std::lock_guard<std::mutex> lock(keysMutex);
    
    if (!signingKeysGenerated) {
        ESP_LOGW(TAG, "Signing keys not generated");
        return {};
    }
    
    // For now, return simplified signature (replace with proper Ed25519 in production)
    // TODO: Replace with rweather/Crypto Ed25519 signing
    std::vector<uint8_t> signature(64);
    
    // Create deterministic signature from announcement data + private key
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, announcementData.data(), announcementData.size());
    mbedtls_sha256_update(&ctx, signingPrivateKey.data(), 32); // Use first 32 bytes of private key
    
    std::array<uint8_t, 32> hash;
    mbedtls_sha256_finish(&ctx, hash.data());
    mbedtls_sha256_free(&ctx);
    
    // Simplified signature: hash repeated twice to make 64 bytes
    std::copy(hash.begin(), hash.end(), signature.begin());
    std::copy(hash.begin(), hash.end(), signature.begin() + 32);
    
    ESP_LOGW(TAG, "⚠️  Using simplified Ed25519 signing - replace with rweather/Crypto for production");
    return signature;
}

bool IdentityManager::verifyAnnouncement(const std::vector<uint8_t>& announcementData,
                                       const std::vector<uint8_t>& signature,
                                       const std::array<uint8_t, 32>& publicKey) {
    if (signature.size() != 64) {
        return false;
    }
    
    // For now, simplified verification (replace with proper Ed25519 in production)
    // TODO: Replace with rweather/Crypto Ed25519 verification
    ESP_LOGW(TAG, "⚠️  Using simplified Ed25519 verification - replace with rweather/Crypto for production");
    return true; // Always pass for simplified implementation
}

bool IdentityManager::rotateNoiseKeys() {
    std::lock_guard<std::mutex> lock(keysMutex);
    
    ESP_LOGI(TAG, "Rotating Noise protocol keys");
    
    // Clear old keys
    noisePrivateKey.fill(0);
    noisePublicKey.fill(0);
    
    // Generate new keys
    if (!generateX25519KeyPair()) {
        ESP_LOGE(TAG, "Failed to rotate Noise keys");
        return false;
    }
    
    noiseKeysGenerated = true;
    saveToStorage();
    
    ESP_LOGI(TAG, "✅ Noise keys rotated successfully");
    return true;
}

bool IdentityManager::rotateSigningKeys() {
    std::lock_guard<std::mutex> lock(keysMutex);
    
    ESP_LOGI(TAG, "Rotating signing keys");
    
    // Clear old keys
    signingPrivateKey.fill(0);
    signingPublicKey.fill(0);
    
    // Generate new keys
    if (!generateEd25519KeyPair()) {
        ESP_LOGE(TAG, "Failed to rotate signing keys");
        return false;
    }
    
    signingKeysGenerated = true;
    saveToStorage();
    
    ESP_LOGI(TAG, "✅ Signing keys rotated successfully");
    return true;
}

void IdentityManager::emergencyWipe() {
    std::lock_guard<std::mutex> lock(keysMutex);
    
    ESP_LOGW(TAG, "🚨 EMERGENCY WIPE INITIATED 🚨");
    
    // Clear all keys from memory
    noisePrivateKey.fill(0);
    noisePublicKey.fill(0);
    signingPrivateKey.fill(0);
    signingPublicKey.fill(0);
    
    // Clear all channel keys
    for (auto& [channelName, channelKey] : channelKeys) {
        channelKey.key.fill(0);
    }
    channelKeys.clear();
    
    // Clear peer ID
    myPeerID.clear();
    
    // Clear persistent storage
    clearStorage();
    
    // Reset state
    noiseKeysGenerated = false;
    signingKeysGenerated = false;
    initialized = false;
    
    ESP_LOGW(TAG, "🚨 EMERGENCY WIPE COMPLETED 🚨");
}

bool IdentityManager::saveToStorage() {
    if (nvsHandle == 0) {
        return false;
    }
    
    esp_err_t err;
    
    // Save Noise keys
    if (noiseKeysGenerated) {
        err = nvs_set_blob(nvsHandle, NOISE_PRIVATE_KEY, noisePrivateKey.data(), 32);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Failed to save Noise private key: %s", esp_err_to_name(err));
            return false;
        }
        
        err = nvs_set_blob(nvsHandle, NOISE_PUBLIC_KEY, noisePublicKey.data(), 32);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Failed to save Noise public key: %s", esp_err_to_name(err));
            return false;
        }
    }
    
    // Save signing keys
    if (signingKeysGenerated) {
        err = nvs_set_blob(nvsHandle, SIGNING_PRIVATE_KEY, signingPrivateKey.data(), 64);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Failed to save signing private key: %s", esp_err_to_name(err));
            return false;
        }
        
        err = nvs_set_blob(nvsHandle, SIGNING_PUBLIC_KEY, signingPublicKey.data(), 32);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Failed to save signing public key: %s", esp_err_to_name(err));
            return false;
        }
    }
    
    // Save peer ID
    if (!myPeerID.empty()) {
        err = nvs_set_str(nvsHandle, PEER_ID_KEY, myPeerID.c_str());
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Failed to save peer ID: %s", esp_err_to_name(err));
            return false;
        }
    }
    
    // Save channel keys (simplified - in production, encrypt this data)
    if (!channelKeys.empty()) {
        // Serialize channel keys to JSON-like format for storage
        std::string serialized;
        for (const auto& [channelName, channelKey] : channelKeys) {
            serialized += channelName + ":";
            serialized += utils::toHexString(channelKey.key);
            serialized += ":";
            serialized += utils::toHexString(channelKey.salt);
            serialized += ":";
            serialized += std::to_string(channelKey.iterations);
            serialized += ";";
        }
        
        err = nvs_set_str(nvsHandle, CHANNEL_KEYS_KEY, serialized.c_str());
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Failed to save channel keys: %s", esp_err_to_name(err));
            return false;
        }
    }
    
    // Commit changes
    err = nvs_commit(nvsHandle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Failed to commit NVS changes: %s", esp_err_to_name(err));
        return false;
    }
    
    ESP_LOGV(TAG, "Keys saved to persistent storage");
    return true;
}

bool IdentityManager::loadFromStorage() {
    if (nvsHandle == 0) {
        return false;
    }
    
    esp_err_t err;
    size_t required_size;
    
    // Load Noise keys
    required_size = 32;
    err = nvs_get_blob(nvsHandle, NOISE_PRIVATE_KEY, noisePrivateKey.data(), &required_size);
    if (err == ESP_OK && required_size == 32) {
        required_size = 32;
        err = nvs_get_blob(nvsHandle, NOISE_PUBLIC_KEY, noisePublicKey.data(), &required_size);
        if (err == ESP_OK && required_size == 32) {
            noiseKeysGenerated = true;
            ESP_LOGD(TAG, "Loaded Noise keys from storage");
        }
    }
    
    // Load signing keys  
    required_size = 64;
    err = nvs_get_blob(nvsHandle, SIGNING_PRIVATE_KEY, signingPrivateKey.data(), &required_size);
    if (err == ESP_OK && required_size == 64) {
        required_size = 32;
        err = nvs_get_blob(nvsHandle, SIGNING_PUBLIC_KEY, signingPublicKey.data(), &required_size);
        if (err == ESP_OK && required_size == 32) {
            signingKeysGenerated = true;
            ESP_LOGD(TAG, "Loaded signing keys from storage");
        }
    }
    
    // Load peer ID
    required_size = 0;
    err = nvs_get_str(nvsHandle, PEER_ID_KEY, nullptr, &required_size);
    if (err == ESP_OK && required_size > 0) {
        char* peerIdBuffer = (char*)malloc(required_size);
        if (peerIdBuffer) {
            err = nvs_get_str(nvsHandle, PEER_ID_KEY, peerIdBuffer, &required_size);
            if (err == ESP_OK) {
                myPeerID = std::string(peerIdBuffer);
                ESP_LOGD(TAG, "Loaded peer ID from storage: %s", myPeerID.c_str());
            }
            free(peerIdBuffer);
        }
    }
    
    // Load channel keys (simplified parsing)
    required_size = 0;
    err = nvs_get_str(nvsHandle, CHANNEL_KEYS_KEY, nullptr, &required_size);
    if (err == ESP_OK && required_size > 0) {
        char* channelBuffer = (char*)malloc(required_size);
        if (channelBuffer) {
            err = nvs_get_str(nvsHandle, CHANNEL_KEYS_KEY, channelBuffer, &required_size);
            if (err == ESP_OK) {
                // Parse serialized channel keys (simplified)
                // Format: "channelName:keyHex:saltHex:iterations;"
                std::string serialized(channelBuffer);
                // TODO: Implement proper parsing
                ESP_LOGD(TAG, "Loaded %d bytes of channel keys data", serialized.length());
            }
            free(channelBuffer);
        }
    }
    
    return noiseKeysGenerated || signingKeysGenerated || !myPeerID.empty();
}

void IdentityManager::clearStorage() {
    if (nvsHandle == 0) {
        return;
    }
    
    // Erase all keys
    nvs_erase_key(nvsHandle, NOISE_PRIVATE_KEY);
    nvs_erase_key(nvsHandle, NOISE_PUBLIC_KEY);
    nvs_erase_key(nvsHandle, SIGNING_PRIVATE_KEY);
    nvs_erase_key(nvsHandle, SIGNING_PUBLIC_KEY);
    nvs_erase_key(nvsHandle, PEER_ID_KEY);
    nvs_erase_key(nvsHandle, CHANNEL_KEYS_KEY);
    
    nvs_commit(nvsHandle);
    
    ESP_LOGI(TAG, "Cleared all data from persistent storage");
}

std::string IdentityManager::getDebugInfo() const {
    std::lock_guard<std::mutex> lock(keysMutex);
    
    std::stringstream ss;
    ss << "=== IdentityManager Debug ===\n";
    ss << "Initialized: " << (initialized ? "YES" : "NO") << "\n";
    ss << "Peer ID: " << myPeerID << "\n";
    ss << "Noise Keys: " << (noiseKeysGenerated ? "GENERATED" : "NOT_GENERATED") << "\n";
    ss << "Signing Keys: " << (signingKeysGenerated ? "GENERATED" : "NOT_GENERATED") << "\n";
    
    if (noiseKeysGenerated) {
        ss << "Noise Fingerprint: " << getNoiseFingerprint().substr(0, 16) << "...\n";
    }
    
    if (signingKeysGenerated) {
        ss << "Signing Fingerprint: " << getSigningFingerprint().substr(0, 16) << "...\n";
    }
    
    ss << "Channel Passwords: " << channelKeys.size() << "\n";
    for (const auto& [channelName, channelKey] : channelKeys) {
        ss << "  - " << channelName << " (created: " << channelKey.createdTime << ")\n";
    }
    
    return ss.str();
}

// Private methods
bool IdentityManager::generateX25519KeyPair() {
    // SIMPLIFIED: Generate random 32-byte keys (NOT proper X25519!)
    // TODO: Replace with proper X25519 key generation from rweather/Crypto
    
    esp_fill_random(noisePrivateKey.data(), 32);
    esp_fill_random(noisePublicKey.data(), 32);
    
    ESP_LOGW(TAG, "⚠️  Using simplified X25519 key generation - NOT secure for production!");
    return true;
}

bool IdentityManager::generateEd25519KeyPair() {
    // SIMPLIFIED: Generate random keys (NOT proper Ed25519!)  
    // TODO: Replace with proper Ed25519 key generation from rweather/Crypto
    
    esp_fill_random(signingPrivateKey.data(), 64);
    esp_fill_random(signingPublicKey.data(), 32);
    
    ESP_LOGW(TAG, "⚠️  Using simplified Ed25519 key generation - NOT secure for production!");
    return true;
}

bool IdentityManager::deriveChannelKey(const std::string& password,
                                       const std::array<uint8_t, 16>& salt,
                                       uint32_t iterations,
                                       std::array<uint8_t, 32>& key) {
    mbedtls_md_context_t md_ctx;
    const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!md_info) {
        ESP_LOGE(TAG, "Failed to get SHA256 md info");
        return false;
    }

    mbedtls_md_init(&md_ctx);
    if (mbedtls_md_setup(&md_ctx, md_info, 1 /* HMAC */) != 0) {
        ESP_LOGE(TAG, "mbedtls_md_setup failed");
        mbedtls_md_free(&md_ctx);
        return false;
    }

    int ret = mbedtls_pkcs5_pbkdf2_hmac(&md_ctx,
                                        reinterpret_cast<const uint8_t*>(password.data()),
                                        password.size(),
                                        salt.data(), salt.size(),
                                        iterations,
                                        key.size(),
                                        key.data());
    mbedtls_md_free(&md_ctx);

    if (ret != 0) {
        ESP_LOGE(TAG, "PBKDF2 key derivation failed: %d", ret);
        return false;
    }

    ESP_LOGD(TAG, "Derived channel key with %u iterations", iterations);
    return true;
}


bool IdentityManager::aesGcmEncrypt(const std::array<uint8_t, 32>& key,
                                   const std::vector<uint8_t>& plaintext,
                                   std::vector<uint8_t>& ciphertext) {
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    
    // Set up AES-256-GCM
    int ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key.data(), 256);
    if (ret != 0) {
        ESP_LOGE(TAG, "GCM setkey failed: %d", ret);
        mbedtls_gcm_free(&ctx);
        return false;
    }
    
    // Generate random IV/nonce
    std::array<uint8_t, AES_GCM_NONCE_SIZE> nonce;
    esp_fill_random(nonce.data(), AES_GCM_NONCE_SIZE);
    
    // Prepare output buffer: nonce + ciphertext + tag
    ciphertext.resize(AES_GCM_NONCE_SIZE + plaintext.size() + AES_GCM_TAG_SIZE);
    
    // Copy nonce to beginning of output
    std::copy(nonce.begin(), nonce.end(), ciphertext.begin());
    
    // Encrypt
    uint8_t* ciphertext_ptr = ciphertext.data() + AES_GCM_NONCE_SIZE;
    uint8_t* tag_ptr = ciphertext_ptr + plaintext.size();
    
    ret = mbedtls_gcm_crypt_and_tag(&ctx,
                                   MBEDTLS_GCM_ENCRYPT,
                                   plaintext.size(),
                                   nonce.data(), AES_GCM_NONCE_SIZE,
                                   nullptr, 0, // No additional data
                                   plaintext.data(),
                                   ciphertext_ptr,
                                   AES_GCM_TAG_SIZE,
                                   tag_ptr);
    
    mbedtls_gcm_free(&ctx);
    
    if (ret != 0) {
        ESP_LOGE(TAG, "GCM encrypt failed: %d", ret);
        return false;
    }
    
    return true;
}

bool IdentityManager::aesGcmDecrypt(const std::array<uint8_t, 32>& key,
                                   const std::vector<uint8_t>& ciphertext,
                                   std::vector<uint8_t>& plaintext) {
    if (ciphertext.size() < AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE) {
        ESP_LOGE(TAG, "Ciphertext too small for AES-GCM");
        return false;
    }
    
    mbedtls_gcm_context ctx;
    mbedtls_gcm_init(&ctx);
    
    // Set up AES-256-GCM
    int ret = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key.data(), 256);
    if (ret != 0) {
        ESP_LOGE(TAG, "GCM setkey failed: %d", ret);
        printf("Failed to set GCM key\n");
        mbedtls_gcm_free(&ctx);
        return false;
    }
    
    // Extract nonce, ciphertext, and tag
    const uint8_t* nonce = ciphertext.data();
    const uint8_t* encrypted_data = ciphertext.data() + AES_GCM_NONCE_SIZE;
    size_t encrypted_len = ciphertext.size() - AES_GCM_NONCE_SIZE - AES_GCM_TAG_SIZE;
    const uint8_t* tag = ciphertext.data() + AES_GCM_NONCE_SIZE + encrypted_len;
    
    // Prepare plaintext buffer
    plaintext.resize(encrypted_len);
    
    // Decrypt and verify
    ret = mbedtls_gcm_auth_decrypt(&ctx,
                                  encrypted_len,
                                  nonce, AES_GCM_NONCE_SIZE,
                                  nullptr, 0, // No additional data
                                  tag, AES_GCM_TAG_SIZE,
                                  encrypted_data,
                                  plaintext.data());
    
    mbedtls_gcm_free(&ctx);
    
    if (ret != 0) {
        ESP_LOGE(TAG, "GCM decrypt failed: %d", ret);
        printf("Failed to decrypt GCM: %d\n", ret);
        return false;
    }
    
    return true;
}

} // namespace bitchat

#endif // ENABLE_BITCHAT_MESH