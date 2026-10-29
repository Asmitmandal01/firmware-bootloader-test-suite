#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bootloader.h"

/* Wire format for Host -> Device:
 * [sof:2][pkt_type:1][seq_num:2][payload_len:2][payload:64][crc32:4] = 75 bytes fixed frame
 * Wire format for Device -> Host:
 * [sof:2][pkt_type:1][acked_seq:2][status:1][state:1][active_ver:4][crc32:4] = 15 bytes fixed frame
 */
int main(void) {
    uint8_t factory_fw[512];
    for (size_t i = 0; i < sizeof(factory_fw); i++) {
        factory_fw[i] = (uint8_t)(0xA0u ^ (uint8_t)i);
    }

    BL_Context_t ctx;
    BL_Init(&ctx, factory_fw, (uint32_t)sizeof(factory_fw), 0x00010000u); /* Factory v1.0.0 */

    uint8_t rx_wire[75];
    uint8_t tx_wire[15];

    while (fread(rx_wire, 1, sizeof(rx_wire), stdin) == sizeof(rx_wire)) {
        BL_Packet_t pkt;
        memset(&pkt, 0, sizeof(pkt));
        pkt.sof         = (uint16_t)rx_wire[0] | ((uint16_t)rx_wire[1] << 8u);
        pkt.pkt_type    = rx_wire[2];
        pkt.seq_num     = (uint16_t)rx_wire[3] | ((uint16_t)rx_wire[4] << 8u);
        pkt.payload_len = (uint16_t)rx_wire[5] | ((uint16_t)rx_wire[6] << 8u);
        memcpy(pkt.payload, &rx_wire[7], BL_MAX_PAYLOAD_BYTES);
        pkt.crc32       = (uint32_t)rx_wire[71]
                        | ((uint32_t)rx_wire[72] << 8u)
                        | ((uint32_t)rx_wire[73] << 16u)
                        | ((uint32_t)rx_wire[74] << 24u);

        BL_Response_t resp;
        (void)BL_ProcessPacket(&ctx, &pkt, &resp);

        tx_wire[0]  = (uint8_t)(resp.sof & 0xFFu);
        tx_wire[1]  = (uint8_t)((resp.sof >> 8u) & 0xFFu);
        tx_wire[2]  = resp.pkt_type;
        tx_wire[3]  = (uint8_t)(resp.acked_seq & 0xFFu);
        tx_wire[4]  = (uint8_t)((resp.acked_seq >> 8u) & 0xFFu);
        tx_wire[5]  = resp.status_code;
        tx_wire[6]  = resp.fsm_state;
        tx_wire[7]  = (uint8_t)(resp.active_version & 0xFFu);
        tx_wire[8]  = (uint8_t)((resp.active_version >> 8u) & 0xFFu);
        tx_wire[9]  = (uint8_t)((resp.active_version >> 16u) & 0xFFu);
        tx_wire[10] = (uint8_t)((resp.active_version >> 24u) & 0xFFu);
        tx_wire[11] = (uint8_t)(resp.crc32 & 0xFFu);
        tx_wire[12] = (uint8_t)((resp.crc32 >> 8u) & 0xFFu);
        tx_wire[13] = (uint8_t)((resp.crc32 >> 16u) & 0xFFu);
        tx_wire[14] = (uint8_t)((resp.crc32 >> 24u) & 0xFFu);

        fwrite(tx_wire, 1, sizeof(tx_wire), stdout);
        fflush(stdout);
    }

    return 0;
}
