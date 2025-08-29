#ifdef ENABLE_BITCHAT_MESH

#include "BitchatPacket.h"

namespace bitchat {

// Initialize static members
const std::array<uint8_t, 8> SpecialRecipients::BROADCAST = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

} // namespace bitchat

#endif // ENABLE_BITCHAT_MESH