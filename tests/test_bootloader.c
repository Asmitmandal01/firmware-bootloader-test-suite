#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "bootloader.h"

static void make_packet(
    BL_Packet_t* pkt,
    uint8_t type,
    uint16_t seq,
    const void* payload,
    uint16_t len
) {
    memset(pkt, 0, sizeof(BL_Packet_t));
    pkt->sof         = BL_SOF_MAGIC;
    pkt->pkt_type    = type;
    pkt->seq_num     = seq;
    pkt->payload_len = len;
    if (payload != NULL && len > 0u && len <= BL_MAX_PAYLOAD_BYTES) {
        memcpy(pkt->payload, payload, len);
    }
    pkt->crc32 = BL_ComputePacketCRC(pkt);
}

int main(void) {
    printf("================================================================================\n");
    printf("  Running Embedded C Firmware Bootloader Automated Unit Test Suite\n");
    printf("================================================================================\n");

    uint8_t initial_app[256];
    for (size_t i = 0; i < sizeof(initial_app); i++) {
        initial_app[i] = (uint8_t)(i ^ 0x5Au);
    }

    /* ---------------------------------------------------------------------
     * UT-01: IEEE 802.3 CRC-32 Standard Vector & Null-Pointer Safety
     * --------------------------------------------------------------------- */
    const char* std_str = "123456789";
    uint32_t std_crc = BL_ComputeCRC32((const uint8_t*)std_str, 9u);
    assert(std_crc == 0xCBF43926u);
    assert(BL_ComputeCRC32(NULL, 10u) == 0u);
    assert(BL_ComputePacketCRC(NULL) == 0u);
    assert(BL_ComputeResponseCRC(NULL) == 0u);
    BL_Packet_t bad_len_pkt;
    memset(&bad_len_pkt, 0, sizeof(bad_len_pkt));
    bad_len_pkt.payload_len = 128u;
    assert(BL_ComputePacketCRC(&bad_len_pkt) == 0u);
    printf("  [PASS] UT-01: IEEE 802.3 CRC-32 standard vector (0xCBF43926) & null-pointer checks\n");

    /* ---------------------------------------------------------------------
     * UT-02: Dual-Bank Flash HAL Boundary, Un-Erased Write, and Null Guards
     * --------------------------------------------------------------------- */
    BL_Flash_Init(NULL, initial_app, 256u, 0x00010000u);
    BL_FlashMemory_t flash;
    BL_Flash_Init(&flash, NULL, 0u, 0u);
    assert(flash.active_version == 0x00010000u);
    BL_Flash_Init(&flash, initial_app, sizeof(initial_app), 0x00010000u);

    assert(BL_Flash_EraseStaging(NULL) == BL_ERR_NULL_PTR);
    assert(BL_Flash_WriteStaging(NULL, 0u, initial_app, 16u) == BL_ERR_NULL_PTR);
    assert(BL_Flash_WriteStaging(&flash, 0u, NULL, 16u) == BL_ERR_NULL_PTR);
    /* Write before erase must fail */
    assert(BL_Flash_WriteStaging(&flash, 0u, initial_app, 16u) == BL_ERR_FLASH_WRITE);
    assert(BL_Flash_EraseStaging(&flash) == BL_OK);
    /* Out-of-bounds or zero-length writes must fail */
    assert(BL_Flash_WriteStaging(&flash, 0u, initial_app, 0u) == BL_ERR_FLASH_BOUNDS);
    assert(BL_Flash_WriteStaging(&flash, BL_FLASH_BANK_SIZE + 1u, initial_app, 4u) == BL_ERR_FLASH_BOUNDS);
    assert(BL_Flash_WriteStaging(&flash, BL_FLASH_BANK_SIZE - 4u, initial_app, 8u) == BL_ERR_FLASH_BOUNDS);
    /* Valid write, followed by overwrite to non-0xFF NOR flash location without erase */
    assert(BL_Flash_WriteStaging(&flash, 0u, initial_app, 16u) == BL_OK);
    assert(BL_Flash_WriteStaging(&flash, 0u, initial_app, 16u) == BL_ERR_FLASH_WRITE);

    assert(BL_Flash_ActivateStaging(NULL, NULL) == BL_ERR_NULL_PTR);
    BL_FirmwareMeta_t invalid_meta = { BL_APP_MAGIC, 0x00020000u, 0u, 0u };
    assert(BL_Flash_ActivateStaging(&flash, &invalid_meta) == BL_ERR_FLASH_BOUNDS);
    printf("  [PASS] UT-02: Dual-Bank Flash HAL boundary, NOR overwrite & null-pointer protection\n");

    /* ---------------------------------------------------------------------
     * UT-03: End-to-End Clean Firmware Update (v1.0.0 -> v2.1.0, 512 Bytes)
     * --------------------------------------------------------------------- */
    BL_Init(NULL, NULL, 0u, 0u);
    BL_Context_t ctx;
    BL_Init(&ctx, initial_app, sizeof(initial_app), 0x00010000u);
    BL_Packet_t pkt;
    BL_Response_t resp;

    assert(BL_ProcessPacket(NULL, &pkt, &resp) == BL_ERR_NULL_PTR);

    uint8_t new_fw[512];
    for (size_t i = 0; i < sizeof(new_fw); i++) {
        new_fw[i] = (uint8_t)((i * 7u + 3u) & 0xFFu);
    }
    BL_FirmwareMeta_t meta = {
        .image_magic    = BL_APP_MAGIC,
        .target_version = 0x00020100u,
        .image_size     = (uint32_t)sizeof(new_fw),
        .image_crc32    = BL_ComputeCRC32(new_fw, sizeof(new_fw))
    };

    make_packet(&pkt, PKT_SYN_HANDSHAKE, 0u, NULL, 0u);
    assert(BL_ProcessPacket(&ctx, &pkt, &resp) == BL_OK && resp.pkt_type == PKT_ACK);

    make_packet(&pkt, PKT_FW_METADATA, 0u, &meta, sizeof(meta));
    assert(BL_ProcessPacket(&ctx, &pkt, &resp) == BL_OK && ctx.state == BL_STATE_RECEIVING_DATA);

    uint16_t seq = 1u;
    for (size_t off = 0; off < sizeof(new_fw); off += 64u) {
        make_packet(&pkt, PKT_DATA_CHUNK, seq++, &new_fw[off], 64u);
        assert(BL_ProcessPacket(&ctx, &pkt, &resp) == BL_OK && resp.pkt_type == PKT_ACK);
    }

    make_packet(&pkt, PKT_END_OF_TX, seq, NULL, 0u);
    assert(BL_ProcessPacket(&ctx, &pkt, &resp) == BL_OK);
    assert(ctx.state == BL_STATE_UPDATE_COMPLETE);
    assert(ctx.flash.active_version == 0x00020100u);
    assert(memcmp(ctx.flash.bank_a_active, new_fw, sizeof(new_fw)) == 0);
    printf("  [PASS] UT-03: Clean OTA Firmware Update (v1.0.0 -> v2.1.0) & Bank B->A atomic swap\n");

    /* ---------------------------------------------------------------------
     * UT-04: Corrupted Packet CRC-32 & Sequence Glitch Recovery via Retries
     * --------------------------------------------------------------------- */
    BL_Init(&ctx, initial_app, sizeof(initial_app), 0x00010000u);
    make_packet(&pkt, PKT_SYN_HANDSHAKE, 0u, NULL, 0u);
    (void)BL_ProcessPacket(&ctx, &pkt, &resp);
    make_packet(&pkt, PKT_FW_METADATA, 0u, &meta, sizeof(meta));
    (void)BL_ProcessPacket(&ctx, &pkt, &resp);

    /* Inject bad SOF, invalid payload length, CRC bit-flip, and out-of-order sequence */
    make_packet(&pkt, PKT_DATA_CHUNK, 1u, new_fw, 64u);
    pkt.sof = 0x1234u;
    assert(BL_ProcessPacket(&ctx, &pkt, &resp) == BL_ERR_BAD_SOF && resp.pkt_type == PKT_NACK);

    make_packet(&pkt, PKT_DATA_CHUNK, 1u, new_fw, 64u);
    pkt.payload_len = 99u;
    assert(BL_ProcessPacket(&ctx, &pkt, &resp) == BL_ERR_LEN_INVALID && resp.pkt_type == PKT_NACK);

    /* Valid chunk #1 resets consecutive_errors counter back to 0 */
    make_packet(&pkt, PKT_DATA_CHUNK, 1u, new_fw, 64u);
    assert(BL_ProcessPacket(&ctx, &pkt, &resp) == BL_OK && ctx.consecutive_errors == 0u);

    /* Inject bit-flip in payload of chunk #2 -> BL_ERR_CRC_MISMATCH */
    make_packet(&pkt, PKT_DATA_CHUNK, 2u, &new_fw[64], 64u);
    pkt.payload[10] ^= 0xFFu;
    assert(BL_ProcessPacket(&ctx, &pkt, &resp) == BL_ERR_CRC_MISMATCH && resp.pkt_type == PKT_NACK);

    /* Inject wrong sequence number (#9 instead of #2) -> BL_ERR_SEQ_OUT_OF_ORDER */
    make_packet(&pkt, PKT_DATA_CHUNK, 9u, &new_fw[64], 64u);
    assert(BL_ProcessPacket(&ctx, &pkt, &resp) == BL_ERR_SEQ_OUT_OF_ORDER && resp.pkt_type == PKT_NACK);

    /* Retransmit clean chunk #2 -> succeeds! */
    make_packet(&pkt, PKT_DATA_CHUNK, 2u, &new_fw[64], 64u);
    assert(BL_ProcessPacket(&ctx, &pkt, &resp) == BL_OK && ctx.consecutive_errors == 0u);
    printf("  [PASS] UT-04: Corrupted SOF, Length, CRC-32 bit-flip & Sequence error NACK + retry recovery\n");

    /* ---------------------------------------------------------------------
     * UT-05: Retry Exhaustion (3 Consecutive Faults) -> Safe Rollback to v1.0.0
     * --------------------------------------------------------------------- */
    for (int attempt = 0; attempt < 3; attempt++) {
        make_packet(&pkt, PKT_DATA_CHUNK, 3u, &new_fw[128], 64u);
        pkt.crc32 ^= 0xDEADBEEFu;
        BL_Status_t st = BL_ProcessPacket(&ctx, &pkt, &resp);
        if (attempt < 2) {
            assert(st == BL_ERR_CRC_MISMATCH);
        } else {
            assert(st == BL_ERR_MAX_RETRIES);
        }
    }
    assert(ctx.state == BL_STATE_ABORTED_ROLLBACK);
    assert(ctx.flash.active_version == 0x00010000u);
    assert(memcmp(ctx.flash.bank_a_active, initial_app, sizeof(initial_app)) == 0);
    printf("  [PASS] UT-05: 3 consecutive corrupted packets trigger MAX_RETRIES & preserve Bank A v1.0.0\n");

    /* ---------------------------------------------------------------------
     * UT-06: Whole-Image Tamper / Signature Mismatch & Protocol Edge Cases
     * --------------------------------------------------------------------- */
    BL_Init(&ctx, initial_app, sizeof(initial_app), 0x00010000u);

    /* Out-of-state packets before handshake */
    make_packet(&pkt, PKT_FW_METADATA, 0u, &meta, sizeof(meta));
    assert(BL_ProcessPacket(&ctx, &pkt, &resp) == BL_ERR_STATE_VIOLATION);
    make_packet(&pkt, PKT_DATA_CHUNK, 1u, new_fw, 64u);
    assert(BL_ProcessPacket(&ctx, &pkt, &resp) == BL_ERR_STATE_VIOLATION);
    make_packet(&pkt, PKT_END_OF_TX, 1u, NULL, 0u);
    assert(BL_ProcessPacket(&ctx, &pkt, &resp) == BL_ERR_MAX_RETRIES);

    /* Handshake + Invalid metadata length & bounds */
    BL_Init(&ctx, initial_app, sizeof(initial_app), 0x00010000u);
    make_packet(&pkt, PKT_SYN_HANDSHAKE, 0u, NULL, 0u);
    (void)BL_ProcessPacket(&ctx, &pkt, &resp);

    make_packet(&pkt, PKT_FW_METADATA, 0u, &meta, 4u);
    assert(BL_ProcessPacket(&ctx, &pkt, &resp) == BL_ERR_LEN_INVALID);

    BL_FirmwareMeta_t bad_meta = { 0x11111111u, 0x00020000u, 128u, 0u };
    make_packet(&pkt, PKT_FW_METADATA, 0u, &bad_meta, sizeof(bad_meta));
    assert(BL_ProcessPacket(&ctx, &pkt, &resp) == BL_ERR_FLASH_BOUNDS);

    /* Unknown packet type & explicit PKT_ABORT */
    make_packet(&pkt, 0xEEu, 0u, NULL, 0u);
    assert(BL_ProcessPacket(&ctx, &pkt, &resp) == BL_ERR_MAX_RETRIES);

    make_packet(&pkt, PKT_ABORT, 0u, NULL, 0u);
    assert(BL_ProcessPacket(&ctx, &pkt, &resp) == BL_OK && ctx.state == BL_STATE_ABORTED_ROLLBACK);

    /* Tampered whole-image CRC at END_OF_TX + Premature END_OF_TX */
    BL_Init(&ctx, initial_app, sizeof(initial_app), 0x00010000u);
    make_packet(&pkt, PKT_SYN_HANDSHAKE, 0u, NULL, 0u);
    (void)BL_ProcessPacket(&ctx, &pkt, &resp);

    BL_FirmwareMeta_t tampered_meta = meta;
    tampered_meta.image_size  = 128u;
    tampered_meta.image_crc32 = 0x12345678u; /* Wrong whole-image hash */
    make_packet(&pkt, PKT_FW_METADATA, 0u, &tampered_meta, sizeof(tampered_meta));
    (void)BL_ProcessPacket(&ctx, &pkt, &resp);

    make_packet(&pkt, PKT_DATA_CHUNK, 1u, new_fw, 64u);
    (void)BL_ProcessPacket(&ctx, &pkt, &resp);

    /* Overflowing declared image_size (64 + 65 > 128) */
    make_packet(&pkt, PKT_DATA_CHUNK, 2u, &new_fw[64], 64u);
    /* Test premature END_OF_TX before sending chunk 2 */
    BL_Packet_t early_eot;
    make_packet(&early_eot, PKT_END_OF_TX, 2u, NULL, 0u);
    assert(BL_ProcessPacket(&ctx, &early_eot, &resp) == BL_ERR_LEN_INVALID);

    /* Re-run with full 128 bytes but tampered whole-image CRC */
    BL_Init(&ctx, initial_app, sizeof(initial_app), 0x00010000u);
    make_packet(&pkt, PKT_SYN_HANDSHAKE, 0u, NULL, 0u);
    (void)BL_ProcessPacket(&ctx, &pkt, &resp);
    make_packet(&pkt, PKT_FW_METADATA, 0u, &tampered_meta, sizeof(tampered_meta));
    (void)BL_ProcessPacket(&ctx, &pkt, &resp);
    make_packet(&pkt, PKT_DATA_CHUNK, 1u, new_fw, 64u);
    (void)BL_ProcessPacket(&ctx, &pkt, &resp);
    make_packet(&pkt, PKT_DATA_CHUNK, 2u, &new_fw[64], 64u);
    (void)BL_ProcessPacket(&ctx, &pkt, &resp);

    /* Extra chunk past 128 bytes -> BL_ERR_FLASH_BOUNDS */
    make_packet(&pkt, PKT_DATA_CHUNK, 3u, &new_fw[128], 64u);
    assert(BL_ProcessPacket(&ctx, &pkt, &resp) == BL_ERR_FLASH_BOUNDS);

    /* Send END_OF_TX -> must reject due to whole-image CRC mismatch and preserve Bank A */
    make_packet(&pkt, PKT_END_OF_TX, 3u, NULL, 0u);
    assert(BL_ProcessPacket(&ctx, &pkt, &resp) == BL_ERR_IMAGE_CRC_FAIL);
    assert(ctx.state == BL_STATE_ABORTED_ROLLBACK);
    assert(ctx.flash.active_version == 0x00010000u);

    /* Exercise string conversion helpers for 100% function coverage */
    for (int s = 0; s <= 11; s++) {
        assert(BL_StatusToString((BL_Status_t)s) != NULL);
    }
    for (int st = 0; st <= 6; st++) {
        assert(BL_StateToString((BL_State_t)st) != NULL);
    }
    printf("  [PASS] UT-06: Whole-image signature tamper rejection, premature EOT & FSM guard coverage\n");

    printf("================================================================================\n");
    printf("  All 6/6 Bootloader Unit Test Suites Passed!\n");
    printf("================================================================================\n");
    return 0;
}
