#include "bootloader.h"
#include <string.h>

void BL_Flash_Init(
    BL_FlashMemory_t* flash,
    const uint8_t* initial_fw,
    uint32_t initial_size,
    uint32_t initial_ver
) {
    if (flash == NULL) {
        return;
    }
    memset(flash->bank_a_active, 0xFF, BL_FLASH_BANK_SIZE);
    memset(flash->bank_b_staging, 0xFF, BL_FLASH_BANK_SIZE);
    flash->bank_b_erased   = false;
    flash->flash_write_ops = 0u;
    flash->flash_erase_ops = 0u;

    if (initial_fw != NULL && initial_size > 0u && initial_size <= BL_FLASH_BANK_SIZE) {
        memcpy(flash->bank_a_active, initial_fw, initial_size);
        flash->active_version    = initial_ver;
        flash->active_image_size = initial_size;
        flash->active_image_crc  = BL_ComputeCRC32(initial_fw, initial_size);
    } else {
        flash->active_version    = 0x00010000u; /* Default v1.0.0 */
        flash->active_image_size = 0u;
        flash->active_image_crc  = 0u;
    }
}

BL_Status_t BL_Flash_EraseStaging(BL_FlashMemory_t* flash) {
    if (flash == NULL) {
        return BL_ERR_NULL_PTR;
    }
    memset(flash->bank_b_staging, 0xFF, BL_FLASH_BANK_SIZE);
    flash->bank_b_erased = true;
    flash->flash_erase_ops++;
    return BL_OK;
}

BL_Status_t BL_Flash_WriteStaging(
    BL_FlashMemory_t* flash,
    uint32_t offset,
    const uint8_t* data,
    uint32_t len
) {
    if (flash == NULL || data == NULL) {
        return BL_ERR_NULL_PTR;
    }
    if (!flash->bank_b_erased) {
        return BL_ERR_FLASH_WRITE;
    }
    if (len == 0u || offset > BL_FLASH_BANK_SIZE || (offset + len) > BL_FLASH_BANK_SIZE) {
        return BL_ERR_FLASH_BOUNDS;
    }
    /* Verify target NOR flash bytes are erased (0xFF) before programming */
    for (uint32_t i = 0u; i < len; i++) {
        if (flash->bank_b_staging[offset + i] != 0xFFu) {
            return BL_ERR_FLASH_WRITE;
        }
    }
    memcpy(&flash->bank_b_staging[offset], data, len);
    flash->flash_write_ops++;
    return BL_OK;
}

BL_Status_t BL_Flash_ActivateStaging(BL_FlashMemory_t* flash, const BL_FirmwareMeta_t* meta) {
    if (flash == NULL || meta == NULL) {
        return BL_ERR_NULL_PTR;
    }
    if (meta->image_size == 0u || meta->image_size > BL_FLASH_BANK_SIZE) {
        return BL_ERR_FLASH_BOUNDS;
    }
    uint32_t computed_crc = BL_ComputeCRC32(flash->bank_b_staging, meta->image_size);
    if (computed_crc != meta->image_crc32) {
        return BL_ERR_IMAGE_CRC_FAIL;
    }
    /* Atomic Dual-Bank Swap: Copy verified staging Bank B into active Bank A */
    memset(flash->bank_a_active, 0xFF, BL_FLASH_BANK_SIZE);
    memcpy(flash->bank_a_active, flash->bank_b_staging, meta->image_size);
    flash->active_version    = meta->target_version;
    flash->active_image_size = meta->image_size;
    flash->active_image_crc  = computed_crc;
    return BL_OK;
}
