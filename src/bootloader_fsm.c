#include "bootloader.h"
#include <string.h>

static void build_response(
    const BL_Context_t* ctx,
    uint8_t pkt_type,
    uint16_t seq,
    BL_Status_t status,
    BL_Response_t* resp_out
) {
    resp_out->sof            = BL_SOF_MAGIC;
    resp_out->pkt_type       = pkt_type;
    resp_out->acked_seq      = seq;
    resp_out->status_code    = (uint8_t)status;
    resp_out->fsm_state      = (uint8_t)ctx->state;
    resp_out->active_version = ctx->flash.active_version;
    resp_out->crc32          = BL_ComputeResponseCRC(resp_out);
}

static BL_Status_t handle_recoverable_error(
    BL_Context_t* ctx,
    uint16_t seq,
    BL_Status_t err_status,
    BL_Response_t* resp_out
) {
    ctx->consecutive_errors++;
    ctx->total_nacks_tx++;
    if (ctx->consecutive_errors >= BL_MAX_RETRIES) {
        ctx->state = BL_STATE_ABORTED_ROLLBACK;
        ctx->rollback_count++;
        build_response(ctx, PKT_NACK, seq, BL_ERR_MAX_RETRIES, resp_out);
        return BL_ERR_MAX_RETRIES;
    }
    build_response(ctx, PKT_NACK, seq, err_status, resp_out);
    return err_status;
}

void BL_Init(
    BL_Context_t* ctx,
    const uint8_t* initial_fw,
    uint32_t initial_size,
    uint32_t initial_ver
) {
    if (ctx == NULL) {
        return;
    }
    memset(ctx, 0, sizeof(BL_Context_t));
    ctx->state = BL_STATE_IDLE;
    BL_Flash_Init(&ctx->flash, initial_fw, initial_size, initial_ver);
}

BL_Status_t BL_ProcessPacket(
    BL_Context_t* ctx,
    const BL_Packet_t* pkt,
    BL_Response_t* resp_out
) {
    if (ctx == NULL || pkt == NULL || resp_out == NULL) {
        return BL_ERR_NULL_PTR;
    }
    ctx->total_packets_rx++;

    /* Step 1: Validate Start-of-Frame (SOF) Magic */
    if (pkt->sof != BL_SOF_MAGIC) {
        return handle_recoverable_error(ctx, pkt->seq_num, BL_ERR_BAD_SOF, resp_out);
    }

    /* Step 2: Validate Payload Length Bound */
    if (pkt->payload_len > BL_MAX_PAYLOAD_BYTES) {
        return handle_recoverable_error(ctx, pkt->seq_num, BL_ERR_LEN_INVALID, resp_out);
    }

    /* Step 3: Validate Packet-Level IEEE 802.3 CRC-32 */
    uint32_t expected_crc = BL_ComputePacketCRC(pkt);
    if (pkt->crc32 != expected_crc) {
        ctx->crc_error_count++;
        return handle_recoverable_error(ctx, pkt->seq_num, BL_ERR_CRC_MISMATCH, resp_out);
    }

    /* Step 4: Dispatch by Packet Type & Current FSM State */
    switch ((BL_PacketType_t)pkt->pkt_type) {
        case PKT_SYN_HANDSHAKE: {
            ctx->state              = BL_STATE_HANDSHAKE_DONE;
            ctx->expected_seq       = 0u;
            ctx->bytes_received     = 0u;
            ctx->consecutive_errors = 0u;
            memset(&ctx->staged_meta, 0, sizeof(BL_FirmwareMeta_t));
            ctx->total_acks_tx++;
            build_response(ctx, PKT_ACK, pkt->seq_num, BL_OK, resp_out);
            return BL_OK;
        }

        case PKT_FW_METADATA: {
            if (ctx->state != BL_STATE_HANDSHAKE_DONE) {
                return handle_recoverable_error(ctx, pkt->seq_num, BL_ERR_STATE_VIOLATION, resp_out);
            }
            if (pkt->payload_len != sizeof(BL_FirmwareMeta_t)) {
                return handle_recoverable_error(ctx, pkt->seq_num, BL_ERR_LEN_INVALID, resp_out);
            }
            BL_FirmwareMeta_t meta;
            memcpy(&meta, pkt->payload, sizeof(BL_FirmwareMeta_t));
            if (meta.image_magic != BL_APP_MAGIC ||
                meta.image_size == 0u ||
                meta.image_size > BL_FLASH_BANK_SIZE) {
                return handle_recoverable_error(ctx, pkt->seq_num, BL_ERR_FLASH_BOUNDS, resp_out);
            }
            (void)BL_Flash_EraseStaging(&ctx->flash);
            ctx->staged_meta        = meta;
            ctx->state              = BL_STATE_RECEIVING_DATA;
            ctx->expected_seq       = 1u;
            ctx->bytes_received     = 0u;
            ctx->consecutive_errors = 0u;
            ctx->total_acks_tx++;
            build_response(ctx, PKT_ACK, pkt->seq_num, BL_OK, resp_out);
            return BL_OK;
        }

        case PKT_DATA_CHUNK: {
            if (ctx->state != BL_STATE_RECEIVING_DATA) {
                return handle_recoverable_error(ctx, pkt->seq_num, BL_ERR_STATE_VIOLATION, resp_out);
            }
            if (pkt->seq_num != ctx->expected_seq) {
                ctx->seq_error_count++;
                return handle_recoverable_error(ctx, pkt->seq_num, BL_ERR_SEQ_OUT_OF_ORDER, resp_out);
            }
            if (pkt->payload_len == 0u ||
                (ctx->bytes_received + pkt->payload_len) > ctx->staged_meta.image_size) {
                return handle_recoverable_error(ctx, pkt->seq_num, BL_ERR_FLASH_BOUNDS, resp_out);
            }
            BL_Status_t wr_st = BL_Flash_WriteStaging(
                &ctx->flash,
                ctx->bytes_received,
                pkt->payload,
                pkt->payload_len
            );
            if (wr_st != BL_OK) {
                return handle_recoverable_error(ctx, pkt->seq_num, wr_st, resp_out);
            }
            ctx->bytes_received += pkt->payload_len;
            ctx->expected_seq++;
            ctx->consecutive_errors = 0u;
            ctx->total_acks_tx++;
            build_response(ctx, PKT_ACK, pkt->seq_num, BL_OK, resp_out);
            return BL_OK;
        }

        case PKT_END_OF_TX: {
            if (ctx->state != BL_STATE_RECEIVING_DATA) {
                return handle_recoverable_error(ctx, pkt->seq_num, BL_ERR_STATE_VIOLATION, resp_out);
            }
            if (ctx->bytes_received != ctx->staged_meta.image_size) {
                ctx->state = BL_STATE_ABORTED_ROLLBACK;
                ctx->rollback_count++;
                ctx->total_nacks_tx++;
                build_response(ctx, PKT_NACK, pkt->seq_num, BL_ERR_LEN_INVALID, resp_out);
                return BL_ERR_LEN_INVALID;
            }
            ctx->state = BL_STATE_VERIFYING_IMAGE;
            BL_Status_t act_st = BL_Flash_ActivateStaging(&ctx->flash, &ctx->staged_meta);
            if (act_st != BL_OK) {
                /* Whole-image CRC-32 failed! Abort update and preserve Bank A */
                ctx->state = BL_STATE_ABORTED_ROLLBACK;
                ctx->rollback_count++;
                ctx->total_nacks_tx++;
                build_response(ctx, PKT_NACK, pkt->seq_num, act_st, resp_out);
                return act_st;
            }
            ctx->state = BL_STATE_UPDATE_COMPLETE;
            ctx->consecutive_errors = 0u;
            ctx->total_acks_tx++;
            build_response(ctx, PKT_ACK, pkt->seq_num, BL_OK, resp_out);
            return BL_OK;
        }

        case PKT_ABORT: {
            ctx->state = BL_STATE_ABORTED_ROLLBACK;
            ctx->rollback_count++;
            ctx->total_acks_tx++;
            build_response(ctx, PKT_ACK, pkt->seq_num, BL_OK, resp_out);
            return BL_OK;
        }

        default: {
            return handle_recoverable_error(ctx, pkt->seq_num, BL_ERR_STATE_VIOLATION, resp_out);
        }
    }
}

const char* BL_StatusToString(BL_Status_t status) {
    switch (status) {
        case BL_OK:                   return "BL_OK";
        case BL_ERR_NULL_PTR:         return "BL_ERR_NULL_PTR";
        case BL_ERR_BAD_SOF:          return "BL_ERR_BAD_SOF";
        case BL_ERR_CRC_MISMATCH:     return "BL_ERR_CRC_MISMATCH";
        case BL_ERR_SEQ_OUT_OF_ORDER: return "BL_ERR_SEQ_OUT_OF_ORDER";
        case BL_ERR_LEN_INVALID:      return "BL_ERR_LEN_INVALID";
        case BL_ERR_FLASH_BOUNDS:     return "BL_ERR_FLASH_BOUNDS";
        case BL_ERR_FLASH_WRITE:      return "BL_ERR_FLASH_WRITE";
        case BL_ERR_IMAGE_CRC_FAIL:   return "BL_ERR_IMAGE_CRC_FAIL";
        case BL_ERR_STATE_VIOLATION:  return "BL_ERR_STATE_VIOLATION";
        case BL_ERR_MAX_RETRIES:      return "BL_ERR_MAX_RETRIES";
        default:                      return "BL_ERR_UNKNOWN";
    }
}

const char* BL_StateToString(BL_State_t state) {
    switch (state) {
        case BL_STATE_IDLE:             return "IDLE";
        case BL_STATE_HANDSHAKE_DONE:   return "HANDSHAKE_DONE";
        case BL_STATE_RECEIVING_DATA:   return "RECEIVING_DATA";
        case BL_STATE_VERIFYING_IMAGE:  return "VERIFYING_IMAGE";
        case BL_STATE_UPDATE_COMPLETE:  return "UPDATE_COMPLETE";
        case BL_STATE_ABORTED_ROLLBACK: return "ABORTED_ROLLBACK";
        default:                        return "UNKNOWN_STATE";
    }
}
