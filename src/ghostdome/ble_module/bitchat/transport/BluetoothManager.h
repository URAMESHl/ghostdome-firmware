#pragma once

#ifdef ENABLE_BITCHAT_MESH

#include "ghostdome/ble_module/bitchat/models/BitchatPacket.h"
#include <string>
#include <vector>
#include <functional>
#include <mutex>
#include <NimBLEDevice.h>
#include <NimBLEAdvertisedDevice.h>

namespace bitchat {

/**
 * Bluetooth Manager - BLE Transport Layer for BitChat
 * 
 * Handles Bluetooth Low Energy communication with BitChat compatible devices.
 * Uses Nordic NimBLE stack for ESP32 compatibility.
 * 
 * BitChat Protocol over BLE:
 * - Service UUID: 6E400001-B5A3-F393-E0A9-E50E24DCCA9E
 * - TX Char UUID: 6E400002-B5A3-F393-E0A9-E50E24DCCA9E (write to peer)
 * - RX Char UUID: 6E400003-B5A3-F393-E0A9-E50E24DCCA9E (read from peer)
 */
class BluetoothManager {
public:
    // Callback types
    using PacketCallback = std::function<void(const BitchatPacket&, const std::string&)>;
    using ConnectionCallback = std::function<void(const std::string&, bool)>;
    
    BluetoothManager();
    ~BluetoothManager();
    
    // Core operations
    bool initialize(const std::string& deviceName);
    bool startServices();
    void stopServices();
    bool isRunning() const { return isActive; }
    
    // Messaging
    bool broadcastPacket(const BitchatPacket& packet);
    bool sendPacketToPeer(const BitchatPacket& packet, const std::string& deviceAddress);
    
    // Connection management
    std::vector<std::string> getConnectedDevices() const;
    size_t getConnectionCount() const;
    bool disconnectDevice(const std::string& deviceAddress);
    void disconnectAll();
    
    // Configuration
    void setPacketCallback(PacketCallback callback) { packetCallback = callback; }
    void setConnectionCallback(ConnectionCallback callback) { connectionCallback = callback; }
    
    // BLE parameters
    void setScanParameters(uint16_t interval, uint16_t window);
    void setAdvertisingParameters(uint16_t minInterval, uint16_t maxInterval);
    void setConnectionParameters(uint16_t minInterval, uint16_t maxInterval, 
                               uint16_t latency, uint16_t timeout);

    void addConnectedDevice(const std::string& deviceAddress) {
    std::lock_guard<std::mutex> lock(connectionsMutex);
    connectedDevices.push_back(deviceAddress);
    }

    void removeConnectedDevice(const std::string& deviceAddress) {
    std::lock_guard<std::mutex> lock(connectionsMutex);
    auto it = std::find(connectedDevices.begin(), connectedDevices.end(), deviceAddress);
    if (it != connectedDevices.end()) {
        connectedDevices.erase(it);
    }
    }

    void triggerConnectionCallback(const std::string& deviceAddress, bool connected) {
        if (connectionCallback) {
            connectionCallback(deviceAddress, connected);
        }
    }

    
    // Debug
    std::string getDebugInfo() const;

private:
    // BLE Components
    NimBLEServer* bleServer;
    NimBLEService* bitchatService;
    NimBLECharacteristic* txCharacteristic;
    NimBLECharacteristic* rxCharacteristic;
    NimBLEAdvertising* advertising;
    NimBLEScan* scanner;
    
    // State
    bool isActive;
    std::string deviceName;
    mutable std::mutex connectionsMutex;
    std::vector<std::string> connectedDevices;
    
    // Callbacks
    PacketCallback packetCallback;
    ConnectionCallback connectionCallback;
    
    // BLE Parameters
    uint16_t scanInterval;
    uint16_t scanWindow;
    uint16_t advMinInterval;
    uint16_t advMaxInterval;
    uint16_t connMinInterval;
    uint16_t connMaxInterval;
    uint16_t connLatency;
    uint16_t connTimeout;
    
    // Statistics
    uint32_t packetsSent;
    uint32_t packetsReceived;
    
    // Private methods
    bool setupBLEServer();
    bool setupBLEService();
    bool startAdvertising();
    bool startScanning();
    
    void handleIncomingData(const std::vector<uint8_t>& data, const std::string& deviceAddress);
    
    // BLE Callbacks (static methods)
    static void onConnect(NimBLEServer* server);
    static void onDisconnect(NimBLEServer* server);
    
    public:
    // Service UUIDs (matching BitChat exactly)
    static const std::string BITCHAT_SERVICE_UUID;
    static const std::string BITCHAT_TX_CHAR_UUID;
    static const std::string BITCHAT_RX_CHAR_UUID;
    
    // Connection limits
    static constexpr size_t MAX_CONNECTIONS = 4;

private:

public:
    void processIncomingData(const std::vector<uint8_t>& data, const std::string& deviceAddress);
};

/**
 * BLE Server Callbacks for handling connections
 */
class BitchatServerCallbacks : public NimBLEServerCallbacks {
public:
    BitchatServerCallbacks(BluetoothManager* manager) : bluetoothManager(manager) {}
    
    void onConnect(NimBLEServer* pServer, ble_gap_conn_desc* desc) override;
    void onDisconnect(NimBLEServer* pServer) override; // Disconnect remains single-arg
    
private:
    BluetoothManager* bluetoothManager;
};

/**
 * BLE Characteristic Callbacks for handling data
 */
class BitchatCharacteristicCallbacks : public NimBLECharacteristicCallbacks {
public:
    BitchatCharacteristicCallbacks(BluetoothManager* manager) : bluetoothManager(manager) {}
    
    void onWrite(NimBLECharacteristic* characteristic) override;
    void onRead(NimBLECharacteristic* characteristic) override;
    
private:
    BluetoothManager* bluetoothManager;
    friend class BluetoothManager;
};

/**
 * BLE Scan Callbacks for discovering devices
 */
class BitchatScanCallbacks : public NimBLEAdvertisedDeviceCallbacks {
public:
    BitchatScanCallbacks(BluetoothManager* manager) : bluetoothManager(manager) {}
    void onResult(NimBLEAdvertisedDevice* advertisedDevice) override;
private:
    BluetoothManager* bluetoothManager;
};

} // namespace bitchat

#endif // ENABLE_BITCHAT_MESH