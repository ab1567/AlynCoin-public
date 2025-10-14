enum class WireFrame : uint8_t {
    HANDSHAKE   = 0x01,
    HEIGHT      = 0x02,
    PEER_LIST   = 0x03,
    BLOCK       = 0x04,
    SNAP_META   = 0x05,
    SNAP_CHUNK  = 0x06,
    SNAP_END    = 0x07,
    PING        = 0x08,
    SNAP_ACK    = 0x09,
    SNAP_CTRL   = 0x0A,
    TX          = 0x0B,
    STATE       = 0x0C,
    HEADERS     = 0x0D,
    OTHER       = 0xFF
};
