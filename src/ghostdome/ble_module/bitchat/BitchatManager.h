#pragma once

#ifdef ENABLE_BITCHAT_MESH

#include <memory>
#include <string>
#include <vector>

namespace bitchat {

class BitchatManager {
public:
    BitchatManager();
    ~BitchatManager();
    
    bool initialize();
    bool start();
    void stop();
    void update();
    
    bool sendMessage(const std::string& message, const std::string& recipient = "");
    std::vector<std::string> getActivePeers() const;
    size_t getActivePeerCount() const;
    std::string getNetworkStatus() const;
    
    bool isRunning() const { return running; }

private:
    bool initialized;
    bool running;
    unsigned long lastUpdate;
};

} // namespace bitchat

#endif // ENABLE_BITCHAT_MESH
