#include "bootloader.h"

uint32_t BL_ComputeCRC32(const uint8_t* data, size_t length) {
    if (data == NULL) {
        return 0u;
    }
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < length; i++) {
        crc ^= (uint32_t)data[i];
        for (uint8_t bit = 0; bit < 8u; bit++) {
            if ((crc & 1u) != 0u) {
                crc = (crc >> 1u) ^ 0xEDB88320u;
            } else {
                crc >>= 1u;
            }
        }
    }
    return ~crc;
}

uint32_t BL_ComputePacketCRC(const BL_Packet_t* pkt) {
    if (pkt == NULL || pkt->payload_len > BL_MAX_PAYLOAD_BYTES) {
        return 0u;
    }
    uint8_t buf[BL_HEADER_BYTES + BL_MAX_PAYLOAD_BYTES];
    buf[0] = (uint8_t)(pkt->sof & 0xFFu);
    buf[1] = (uint8_t)((pkt->sof >> 8u) & 0xFFu);
    buf[2] = pkt->pkt_type;
    buf[3] = (uint8_t)(pkt->seq_num & 0xFFu);
    buf[4] = (uint8_t)((pkt->seq_num >> 8u) & 0xFFu);
    buf[5] = (uint8_t)(pkt->payload_len & 0xFFu);
    buf[6] = (uint8_t)((pkt->payload_len >> 8u) & 0xFFu);

    for (uint16_t i = 0; i < pkt->payload_len; i++) {
        buf[BL_HEADER_BYTES + i] = pkt->payload[i];
    }
    return BL_ComputeCRC32(buf, (size_t)BL_HEADER_BYTES + (size_t)pkt->payload_len);
}

uint32_t BL_ComputeResponseCRC(const BL_Response_t* resp) {
    if (resp == NULL) {
        return 0u;
    }
    uint8_t buf[11];
    buf[0]  = (uint8_t)(resp->sof & 0xFFu);
    buf[1]  = (uint8_t)((resp->sof >> 8u) & 0xFFu);
    buf[2]  = resp->pkt_type;
    buf[3]  = (uint8_t)(resp->acked_seq & 0xFFu);
    buf[4]  = (uint8_t)((resp->acked_seq >> 8u) & 0xFFu);
    buf[5]  = resp->status_code;
    buf[6]  = resp->fsm_state;
    buf[7]  = (uint8_t)(resp->active_version & 0xFFu);
    buf[8]  = (uint8_t)((resp->active_version >> 8u) & 0xFFu);
    buf[9]  = (uint8_t)((resp->active_version >> 16u) & 0xFFu);
    buf[10] = (uint8_t)((resp->active_version >> 24u) & 0xFFu);
    return BL_ComputeCRC32(buf, sizeof(buf));
}
