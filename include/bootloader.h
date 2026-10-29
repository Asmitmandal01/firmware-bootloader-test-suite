#ifndef BOOTLOADER_H
#define BOOTLOADER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* =========================================================================
 * 1. Framed Packet Protocol Constants & Types
 * ========================================================================= */
#define BL_SOF_MAGIC          0xAA55u
#define BL_MAX_PAYLOAD_BYTES  64u
#define BL_HEADER_BYTES       7u   /* sof(2) + type(1) + seq(2) + len(2) */
#define BL_CRC_BYTES          4u
#define BL_MAX_RETRIES        3u

/* Flash Partition Geometry (Dual-Bank Anti-Brick Architecture) */
#define BL_FLASH_BANK_SIZE    16384u  /* 16 KB per Application Bank */
#define BL_APP_MAGIC          0xB00710ADu

typedef enum {
    PKT_SYN_HANDSHAKE = 0x01,
    PKT_FW_METADATA   = 0x02,
    PKT_DATA_CHUNK    = 0x03,
    PKT_END_OF_TX     = 0x04,
    PKT_ABORT         = 0x05,
    PKT_ACK           = 0x81,
    PKT_NACK          = 0x82
} BL_PacketType_t;

typedef enum {
    BL_OK                     = 0x00,
    BL_ERR_NULL_PTR           = 0x01,
    BL_ERR_BAD_SOF            = 0x02,
    BL_ERR_CRC_MISMATCH       = 0x03,
    BL_ERR_SEQ_OUT_OF_ORDER   = 0x04,
    BL_ERR_LEN_INVALID        = 0x05,
    BL_ERR_FLASH_BOUNDS       = 0x06,
    BL_ERR_FLASH_WRITE        = 0x07,
    BL_ERR_IMAGE_CRC_FAIL     = 0x08,
    BL_ERR_STATE_VIOLATION    = 0x09,
    BL_ERR_MAX_RETRIES        = 0x0A
} BL_Status_t;

typedef enum {
    BL_STATE_IDLE             = 0,
    BL_STATE_HANDSHAKE_DONE   = 1,
    BL_STATE_RECEIVING_DATA   = 2,
    BL_STATE_VERIFYING_IMAGE  = 3,
    BL_STATE_UPDATE_COMPLETE  = 4,
    BL_STATE_ABORTED_ROLLBACK = 5
} BL_State_t;

/* Host -> Device Framed Packet */
typedef struct {
    uint16_t sof;
    uint8_t  pkt_type;
    uint16_t seq_num;
    uint16_t payload_len;
    uint8_t  payload[BL_MAX_PAYLOAD_BYTES];
    uint32_t crc32;
} BL_Packet_t;

/* Device -> Host ACK/NACK Response Frame */
typedef struct {
    uint16_t sof;
    uint8_t  pkt_type;       /* PKT_ACK or PKT_NACK */
    uint16_t acked_seq;
    uint8_t  status_code;    /* BL_Status_t */
    uint8_t  fsm_state;      /* BL_State_t */
    uint32_t active_version; /* e.g. 0x00010000 for v1.0.0 */
    uint32_t crc32;
} BL_Response_t;

/* Firmware Header Metadata Payload (sent in PKT_FW_METADATA) */
typedef struct {
    uint32_t image_magic;    /* Must equal BL_APP_MAGIC */
    uint32_t target_version; /* e.g. 0x00020100 for v2.1.0 */
    uint32_t image_size;     /* Total firmware size in bytes (1 .. BL_FLASH_BANK_SIZE) */
    uint32_t image_crc32;    /* Expected IEEE 802.3 CRC-32 across entire firmware image */
} BL_FirmwareMeta_t;

/* Dual-Bank Emulated Non-Volatile Flash Memory */
typedef struct {
    uint8_t  bank_a_active[BL_FLASH_BANK_SIZE];  /* Bank A: Running Application */
    uint8_t  bank_b_staging[BL_FLASH_BANK_SIZE]; /* Bank B: OTA Download Staging Slot */
    uint32_t active_version;
    uint32_t active_image_size;
    uint32_t active_image_crc;
    bool     bank_b_erased;
    uint32_t flash_write_ops;
    uint32_t flash_erase_ops;
} BL_FlashMemory_t;

/* Device Bootloader Context */
typedef struct {
    BL_State_t        state;
    BL_FlashMemory_t  flash;
    BL_FirmwareMeta_t staged_meta;
    uint16_t          expected_seq;
    uint32_t          bytes_received;
    uint8_t           consecutive_errors;

    /* Diagnostic Telemetry Counters */
    uint32_t          total_packets_rx;
    uint32_t          total_acks_tx;
    uint32_t          total_nacks_tx;
    uint32_t          crc_error_count;
    uint32_t          seq_error_count;
    uint32_t          rollback_count;
} BL_Context_t;

/* =========================================================================
 * 2. Public API Declarations
 * ========================================================================= */
uint32_t    BL_ComputeCRC32(const uint8_t* data, size_t length);
uint32_t    BL_ComputePacketCRC(const BL_Packet_t* pkt);
uint32_t    BL_ComputeResponseCRC(const BL_Response_t* resp);

void        BL_Flash_Init(BL_FlashMemory_t* flash, const uint8_t* initial_fw, uint32_t initial_size, uint32_t initial_ver);
BL_Status_t BL_Flash_EraseStaging(BL_FlashMemory_t* flash);
BL_Status_t BL_Flash_WriteStaging(BL_FlashMemory_t* flash, uint32_t offset, const uint8_t* data, uint32_t len);
BL_Status_t BL_Flash_ActivateStaging(BL_FlashMemory_t* flash, const BL_FirmwareMeta_t* meta);

void        BL_Init(BL_Context_t* ctx, const uint8_t* initial_fw, uint32_t initial_size, uint32_t initial_ver);
BL_Status_t BL_ProcessPacket(BL_Context_t* ctx, const BL_Packet_t* pkt, BL_Response_t* resp_out);
const char* BL_StatusToString(BL_Status_t status);
const char* BL_StateToString(BL_State_t state);

#endif /* BOOTLOADER_H */
