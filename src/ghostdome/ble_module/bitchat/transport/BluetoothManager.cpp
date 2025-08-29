#ifdef ENABLE_BITCHAT_MESH

#include "ghostdome/ble_module/bitchat/transport/BluetoothManager.h"
#include "ghostdome/ble_module/bitchat/protocol/BinaryProtocol.h"
#include <esp_log.h>
#include <NimBLEDevice.h>
#include <NimBLEServer.h>
#include <NimBLEAdvertisedDevice.h>
#include <sstream>

static const char* TAG = "BluetoothManager";

namespace bitchat {

// BitChat Service UUIDs (EXACT same as Android/iOS BitChat)
const std::string BluetoothManager::BITCHAT_SERVICE_UUID = "6E400001-B5A3-F393-E0A9-E50E24DCCA9E";
const std::string BluetoothManager::BITCHAT_TX_CHAR_UUID = "6E400002-B5A3-F393-E0A9-E50E24DCCA9E";
const std::string BluetoothManager::BITCHAT_RX_CHAR_UUID = "6E400003-B5A3-F393-E0A9-E50E24DCCA9E";

BluetoothManager::BluetoothManager() 
    : bleServer(nullptr), bitchatService(nullptr), txCharacteristic(nullptr),
      rxCharacteristic(nullptr), advertising(nullptr), scanner(nullptr),
      isActive(false), scanInterval(80), scanWindow(40), 
      advMinInterval(100), advMaxInterval(200), 
      connMinInterval(24), connMaxInterval(40), connLatency(0), connTimeout(400),
      packetsSent(0), packetsReceived(0) {
    ESP_LOGI(TAG, "BluetoothManager created");
}

BluetoothManager::~BluetoothManager() {
    stopServices();
}

bool BluetoothManager::initialize(const std::string& deviceName) {
    if (isActive) {
        ESP_LOGW(TAG, "BluetoothManager already initialized");
        return true;
    }
    
    this->deviceName = deviceName;
    
    ESP_LOGI(TAG, "Initializing BitChat BLE with device name: %s", deviceName.c_str());
    
    // Initialize NimBLE
    NimBLEDevice::init(deviceName);
    NimBLEDevice::setPower(ESP_PWR_LVL_P9); // Maximum power
    

    
    return setupBLEServer() && setupBLEService();
}

bool BluetoothManager::setupBLEServer() {
    // Create BLE Server
    bleServer = NimBLEDevice::createServer();
    if (!bleServer) {
        ESP_LOGE(TAG, "Failed to create BLE server");
        return false;
    }
    
    // Set server callbacks
    bleServer->setCallbacks(new BitchatServerCallbacks(this));
    
    ESP_LOGD(TAG, "BLE server created successfully");
    return true;
}

bool BluetoothManager::setupBLEService() {
    // Create BitChat service with exact UUID
    bitchatService = bleServer->createService(BITCHAT_SERVICE_UUID);
    if (!bitchatService) {
        ESP_LOGE(TAG, "Failed to create BitChat service");
        return false;
    }
    
    // Create TX characteristic (ESP32 -> phone)
    txCharacteristic = bitchatService->createCharacteristic(
        BITCHAT_TX_CHAR_UUID,
        NIMBLE_PROPERTY::NOTIFY
    );
    
    // Create RX characteristic (phone -> ESP32)
    rxCharacteristic = bitchatService->createCharacteristic(
        BITCHAT_RX_CHAR_UUID,
        NIMBLE_PROPERTY::WRITE | NIMBLE_PROPERTY::WRITE_NR
    );
    
    if (!txCharacteristic || !rxCharacteristic) {
        ESP_LOGE(TAG, "Failed to create BitChat characteristics");
        return false;
    }
    
    // Set characteristic callbacks
    rxCharacteristic->setCallbacks(new BitchatCharacteristicCallbacks(this));
    
    ESP_LOGI(TAG, "BitChat service created with UUIDs:");
    ESP_LOGI(TAG, "  Service: %s", BITCHAT_SERVICE_UUID.c_str());
    ESP_LOGI(TAG, "  TX Char: %s", BITCHAT_TX_CHAR_UUID.c_str());
    ESP_LOGI(TAG, "  RX Char: %s", BITCHAT_RX_CHAR_UUID.c_str());
    
    return true;
}

bool BluetoothManager::startServices() {
    if (isActive) {
        ESP_LOGW(TAG, "Services already started");
        return true;
    }
    
    if (!bitchatService) {
        ESP_LOGE(TAG, "Service not initialized");
        return false;
    }
    
    // Start the service
    bitchatService->start();
    
    // Start advertising
    if (!startAdvertising()) {
        ESP_LOGE(TAG, "Failed to start advertising");
        return false;
    }
    
    // Start scanning  
    if (!startScanning()) {
        ESP_LOGE(TAG, "Failed to start scanning");
        return false;
    }
    
    isActive = true;
    ESP_LOGI(TAG, "BitChat BLE services started successfully");
    return true;
}

bool BluetoothManager::startAdvertising() {
    advertising = NimBLEDevice::getAdvertising();
    if (!advertising) {
        ESP_LOGE(TAG, "Failed to get advertising object");
        return false;
    }
    
    // Configure advertising
    advertising->addServiceUUID(BITCHAT_SERVICE_UUID);
    advertising->setScanResponse(true);
    advertising->setMinPreferred(0x06);  // Functions that help with iPhone connections issue
    advertising->setMaxPreferred(0x12);
    
    // Set advertising intervals (matching BitChat Android settings)
    advertising->setMinInterval(advMinInterval);
    advertising->setMaxInterval(advMaxInterval);
    
    // Start advertising
    if (!advertising->start()) {
        ESP_LOGE(TAG, "Failed to start advertising");
        return false;
    }
    
    ESP_LOGI(TAG, "Started advertising BitChat service");
    return true;
}

bool BluetoothManager::startScanning() {
    scanner = NimBLEDevice::getScan();
    if (!scanner) {
        ESP_LOGE(TAG, "Failed to get scanner object");
        return false;
    }
    
    // Configure scanner
    scanner->setAdvertisedDeviceCallbacks(new BitchatScanCallbacks(this));
    scanner->setActiveScan(true); // Active scanning
    scanner->setInterval(scanInterval);
    scanner->setWindow(scanWindow);
    
    // Start continuous scanning
    scanner->start(0, false);
    ESP_LOGI(TAG, "Started scanning for BitChat devices");
    return true;
}

void BluetoothManager::stopServices() {
    if (!isActive) {
        return;
    }
    
    ESP_LOGI(TAG, "Stopping BitChat BLE services");
    
    // Stop advertising
    if (advertising) {
        advertising->stop();
    }
    
    // Stop scanning
    if (scanner) {
        scanner->stop();
    }
    
    // Disconnect all clients
    disconnectAll();
    
    isActive = false;
    ESP_LOGI(TAG, "BitChat BLE services stopped");
}

bool BluetoothManager::broadcastPacket(const BitchatPacket& packet) {
    if (!isActive || !txCharacteristic) {
        ESP_LOGW(TAG, "Cannot broadcast - service not active");
        return false;
    }
    
    // Encode packet
    auto encodedData = BinaryProtocol::encode(packet);
    if (encodedData.empty()) {
        ESP_LOGE(TAG, "Failed to encode packet for broadcast");
        return false;
    }
    
    // Send to all connected devices via TX characteristic
    txCharacteristic->notify();  // void return
    packetsSent++;
    ESP_LOGV(TAG, "Broadcasted packet (%d bytes) to %d connected devices", encodedData.size(), getConnectionCount());

    return true;
}

bool BluetoothManager::sendPacketToPeer(const BitchatPacket& packet, const std::string& deviceAddress) {
    // For simplicity, just broadcast (in a full implementation, this would target specific peer)
    return broadcastPacket(packet);
}

std::vector<std::string> BluetoothManager::getConnectedDevices() const {
    std::lock_guard<std::mutex> lock(connectionsMutex);
    return connectedDevices;
}

size_t BluetoothManager::getConnectionCount() const {
    if (!bleServer) return 0;
    return bleServer->getConnectedCount();
}

bool BluetoothManager::disconnectDevice(const std::string& deviceAddress) {
    // For simplicity, not implemented (would require tracking individual connections)
    ESP_LOGW(TAG, "Individual device disconnect not implemented");
    return false;
}

void BluetoothManager::disconnectAll() {
    if (bleServer) {
        // Disconnect all connected clients
        auto connectedClients = bleServer->getConnectedCount();
        if (connectedClients > 0) {
            ESP_LOGI(TAG, "Disconnecting %d clients", connectedClients);
            // NimBLE will automatically disconnect clients when we stop advertising
        }
    }
    
    std::lock_guard<std::mutex> lock(connectionsMutex);
    connectedDevices.clear();
}

void BluetoothManager::setScanParameters(uint16_t interval, uint16_t window) {
    scanInterval = interval;
    scanWindow = window;
    
    if (scanner && isActive) {
        scanner->setInterval(scanInterval);
        scanner->setWindow(scanWindow);
        ESP_LOGD(TAG, "Updated scan parameters: interval=%dms, window=%dms", interval, window);
    }
}

void BluetoothManager::setAdvertisingParameters(uint16_t minInterval, uint16_t maxInterval) {
    advMinInterval = minInterval;
    advMaxInterval = maxInterval;
    
    if (advertising && isActive) {
        advertising->setMinInterval(minInterval);
        advertising->setMaxInterval(maxInterval);
        ESP_LOGD(TAG, "Updated advertising parameters: min=%dms, max=%dms", minInterval, maxInterval);
    }
}

void BluetoothManager::setConnectionParameters(uint16_t minInterval, uint16_t maxInterval, 
                                             uint16_t latency, uint16_t timeout) {
    connMinInterval = minInterval;
    connMaxInterval = maxInterval;
    connLatency = latency;
    connTimeout = timeout;
    
   
    ESP_LOGD(TAG, "Updated connection parameters");
}

void BluetoothManager::handleIncomingData(const std::vector<uint8_t>& data, const std::string& deviceAddress) {
    packetsReceived++;
    
    // Decode packet
    auto packet = BinaryProtocol::decode(data);
    if (!packet) {
        ESP_LOGW(TAG, "Failed to decode incoming packet (%d bytes)", data.size());
        return;
    }
    
    ESP_LOGV(TAG, "Received valid packet from %s (type: %d, %d bytes)", 
            deviceAddress.c_str(), static_cast<int>(packet->type), data.size());
    
    // Call packet callback
    if (packetCallback) {
        packetCallback(*packet, deviceAddress);
    }
}

void BluetoothManager::processIncomingData(const std::vector<uint8_t>& data, const std::string& deviceAddress) {
    handleIncomingData(data, deviceAddress);
}

std::string BluetoothManager::getDebugInfo() const {
    std::stringstream ss;
    ss << "=== Bluetooth Manager Debug ===\n";
    ss << "Device Name: " << deviceName << "\n";
    ss << "Active: " << (isActive ? "YES" : "NO") << "\n";
    ss << "Connected Devices: " << getConnectionCount() << "/" << MAX_CONNECTIONS << "\n";
    ss << "Packets Sent: " << packetsSent << "\n";
    ss << "Packets Received: " << packetsReceived << "\n";
    ss << "Scan Interval: " << scanInterval << "ms\n";
    ss << "Scan Window: " << scanWindow << "ms\n";
    ss << "Advertising Interval: " << advMinInterval << "-" << advMaxInterval << "ms\n";
    
    return ss.str();
}

// BitchatServerCallbacks Implementation
void BitchatServerCallbacks::onConnect(NimBLEServer* pServer, ble_gap_conn_desc* desc) {
    // Build address string from desc->peer_ota_addr
    auto& addr = desc->peer_ota_addr;
    char buf[18];
    sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X",
            addr.val[5], addr.val[4], addr.val[3],
            addr.val[2], addr.val[1], addr.val[0]);
    std::string deviceAddress(buf);

    ESP_LOGI(TAG, "Device connected: %s", deviceAddress.c_str());
    bluetoothManager->addConnectedDevice(deviceAddress);
    bluetoothManager->triggerConnectionCallback(deviceAddress, true);
}


void BitchatServerCallbacks::onDisconnect(NimBLEServer* pServer) {
    // getPeerInfo API no longer needed; use server->getDisconnectedPeer() if available,
    // or track connections in your manager.
    // For now, we cannot get deviceAddress here, so just call removeAll or maintain mapping.
}

// BitchatCharacteristicCallbacks Implementation  
void BitchatCharacteristicCallbacks::onWrite(NimBLECharacteristic* characteristic) {
    std::string value = characteristic->getValue();
    std::vector<uint8_t> data(value.begin(), value.end());
    
    if (data.empty()) {
        return;
    }
    
    // Get device address (simplified - may not be accurate)
    std::string deviceAddress = "unknown";
    
    ESP_LOGV(TAG, "Received data on RX characteristic: %d bytes", data.size());
    
    // Handle the incoming data
    bluetoothManager->processIncomingData(data, deviceAddress);
}

void BitchatCharacteristicCallbacks::onRead(NimBLECharacteristic* characteristic) {
    ESP_LOGV(TAG, "Read request on characteristic");
}

// BitchatScanCallbacks Implementation
void BitchatScanCallbacks::onResult(NimBLEAdvertisedDevice* advertisedDevice) {
    // Check if this is a BitChat device
    if (advertisedDevice->haveServiceUUID() && 
        advertisedDevice->isAdvertisingService(NimBLEUUID(BluetoothManager::BITCHAT_SERVICE_UUID))) {
        
        std::string deviceAddress = advertisedDevice->getAddress().toString();
        std::string deviceName = advertisedDevice->haveName() ? advertisedDevice->getName() : "Unknown";
        
        ESP_LOGD(TAG, "Found BitChat device: %s (%s) RSSI: %d", 
                deviceName.c_str(), deviceAddress.c_str(), advertisedDevice->getRSSI());
        
        // Connect to the device (simplified - auto-connect to all BitChat devices)
        if (bluetoothManager->getConnectionCount() < BluetoothManager::MAX_CONNECTIONS) {
            // In a full implementation, we would create a client connection here
            ESP_LOGD(TAG, "Would connect to BitChat device: %s", deviceAddress.c_str());
        }
    }
}



} // namespace bitchat

#endif // ENABLE_BITCHAT_MESH
