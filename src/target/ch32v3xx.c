/*
 * This file is part of the Black Magic Debug project.
 *
 * Copyright (C) 2011  Black Sphere Technologies Ltd.
 * Written by Gareth McMullin <gareth@blacksphere.co.nz>
 * Copyright (C) 2022-2023 1BitSquared <info@1bitsquared.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * This file implements STM32 target specific functions for detecting
 * the device, providing the XML memory map and Flash memory programming.
 *
 * References:
 * ST doc - RM0008
 *   Reference manual - ch32v3x01xx, ch32v3x02xx, ch32v3x03xx, ch32v3x05xx
 *   and ch32v3x07xx advanced ARM-based 32-bit MCUs
 * ST doc - RM0091
 *   Reference manual - STM32F0x1/STM32F0x2/STM32F0x8
 *   advanced ARM®-based 32-bit MCUs
 * ST doc - RM0360
 *   Reference manual - STM32F030x4/x6/x8/xC and STM32F070x6/xB
 * ST doc - PM0075
 *   Programming manual - ch32v3x0xxx Flash memory microcontrollers
 */

#include "general.h"
#include "target.h"
#include "target_internal.h"
#include "cortexm.h"

typedef struct {
	uint32_t ws;      // 0
	uint32_t key;     //4 aka fpec
	uint32_t obkey;   // 8
	uint32_t statr;   // C
	uint32_t ctlr;    // 10
	uint32_t addr;    //14
	uint32_t filler;  //18
	uint32_t obr;     // 1C
	uint32_t wpr;     // 20
	uint32_t modekey; // 24
} ch32_flash_s;

#define CH32V3XX_FLASH_CONTROLLER_ADDRESS 0x40022000
#define CH32V3XX_UID1                     0x1ffff7e8 // Low bits of UUID

#define CH32V3XX_FMC_CTL_START           (1 << 6)
#define CH32V3XX_FMC_CTL_LK              (1 << 7)
#define CH32V3XX_FMC_CTL_CH32_FASTUNLOCK (1 << 15)
#define CH32V3XX_FMC_CTL_CH32_FASTERASE  (1 << 17)

#define CH32V3XX_FMC_STAT_BUSY    (1 << 0)
#define CH32V3XX_FMC_STAT_WR_BUSY (1 << 1)
#define CH32V3XX_FMC_STAT_WP_ENDF (1 << 5) // end of operation

#define CH32V3XX_KEY1 0x45670123
#define CH32V3XX_KEY2 0xcdef89ab

#define READ_FLASH_REG(target, reg) \
	target_mem_read32(target, CH32V3XX_FLASH_CONTROLLER_ADDRESS + offsetof(ch32_flash_s, reg))
#define WRITE_FLASH_REG(target, reg, value) \
	target_mem_write32(target, CH32V3XX_FLASH_CONTROLLER_ADDRESS + offsetof(ch32_flash_s, reg), value)

const command_s ch32v3x_cmd_list[] = {
	{NULL, NULL, NULL},
};

static bool ch32v3x_flash_erase(target_flash_s *flash, target_addr_t addr, size_t len);
static bool ch32v3x_flash_write(target_flash_s *flash, target_addr_t dest, const void *src, size_t len);

/*
*/
static void ch32v3x_add_flash(target_s *target, uint32_t addr, size_t length, size_t erasesize)
{
	target_flash_s *flash = calloc(1, sizeof(*flash));
	if (!flash) { /* calloc failed: heap exhaustion */
		DEBUG_ERROR("calloc: failed in %s\n", __func__);
		return;
	}

	flash->start = addr;
	flash->length = length;
	flash->blocksize = erasesize;
	flash->erase = ch32v3x_flash_erase;
	flash->write = ch32v3x_flash_write;
	flash->writesize = erasesize;
	flash->erased = 0xff;
	target_add_flash(target, flash);
}

/* Identify ch32v3x */
bool ch32v3xx_probe(target_s *target)
{
	int flash_size = 0;
	int ram_size = 0;
	size_t block_size = 256;

	target->driver = "CH32V3XX";

	uint32_t obr = READ_FLASH_REG(target, obr);
	obr = (obr >> 8) & 3; // SRAM_CODE_MODE

#define MEMORY_CONFIG(x, flash, ram) \
	case x: {                        \
		flash_size = flash;          \
		ram_size = ram;              \
	}; break;
	switch (obr) // See 32.4.6
	{
		MEMORY_CONFIG(0, 192, 128)
		MEMORY_CONFIG(1, 224, 96)
		MEMORY_CONFIG(2, 256, 64)
		MEMORY_CONFIG(3, 288, 32)
	default:
		flash_size = 128; // ?
		ram_size = 32;
		break;
	}

	target_add_ram(target, 0x20000000, ram_size * 1024U);
	ch32v3x_add_flash(target, 0x0, (size_t)flash_size * 1024U, block_size);
	target_add_commands(target, ch32v3x_cmd_list, target->driver);

	return true;
}

/*
*/
static bool ch32v3x_fast_unlock(target_s *target)
{
	// send unlock sequence
	WRITE_FLASH_REG(target, key, CH32V3XX_KEY1);
	WRITE_FLASH_REG(target, key, CH32V3XX_KEY2);

	// send fast unlock sequence
	WRITE_FLASH_REG(target, modekey, CH32V3XX_KEY1);
	WRITE_FLASH_REG(target, modekey, CH32V3XX_KEY2);

	uint32_t v = READ_FLASH_REG(target, ctlr);
	return !(v & CH32V3XX_FMC_CTL_CH32_FASTUNLOCK);
}

static void ch32v3x_wait_not_busy(target_flash_s *flash)
{
	// is it busy  ?
	while (1) {
		uint32_t s = READ_FLASH_REG(flash->t, statr);
		if (!(s & CH32V3XX_FMC_STAT_BUSY))
			return;
	}
}
#if 0
static void ch32v3x_wait_not_wr_busy(target_s *target)
{
    // is it wrbusy  ?
    while (1)
    {
       uint32_t s =  READ_FLASH_REG(target, statr);
        if (!(s & CH32V3XX_FMC_STAT_WR_BUSY))
            return;
    }
}
#endif
/*
*/
static void ch32v3x_ctl_set(target_flash_s *flash, uint32_t bits)
{
	uint32_t v = READ_FLASH_REG(flash->t, ctlr);
	v |= bits;
	WRITE_FLASH_REG(flash->t, ctlr, v);
}

/*
*/
static void ch32v3x_ctl_clear(target_flash_s *flash, uint32_t bits)
{
	uint32_t v = READ_FLASH_REG(flash->t, ctlr);
	v &= ~bits;
	WRITE_FLASH_REG(flash->t, ctlr, v);
}

/**
*/
static void ch32v3x_stat_clear(target_flash_s *flash, uint32_t bits)
{
	uint32_t v = READ_FLASH_REG(flash->t, statr);
	v &= ~bits;
	WRITE_FLASH_REG(flash->t, statr, v);
}

/*
*/
static bool ch32v3x_fast_lock(target_flash_s *flash)
{
	ch32v3x_ctl_set(flash, CH32V3XX_FMC_CTL_LK);
	return true;
}

/*
*/
static bool ch32v3x_flash_erase(target_flash_s *flash, target_addr_t addr, size_t len)
{
	//(void)flash;
	(void)addr;
	(void)len;
	ch32v3x_fast_unlock(flash->t);

	uint32_t cur_addr = addr;
	uint32_t end_addr = cur_addr + len;
	while (cur_addr < end_addr) {
		ch32v3x_ctl_set(flash, CH32V3XX_FMC_CTL_CH32_FASTERASE);
		WRITE_FLASH_REG(flash->t, addr, cur_addr);
		ch32v3x_ctl_set(flash, CH32V3XX_FMC_CTL_START);
		ch32v3x_wait_not_busy(flash);
		cur_addr += 256;
		ch32v3x_stat_clear(flash, CH32V3XX_FMC_STAT_WP_ENDF); // clear end of process bit
		ch32v3x_ctl_clear(flash, CH32V3XX_FMC_CTL_CH32_FASTERASE);
		ch32v3x_ctl_clear(flash, CH32V3XX_FMC_CTL_START);
	}
	ch32v3x_fast_lock(flash);
	return true;
}

/*
*/
static bool ch32v3x_flash_write(target_flash_s *flash, target_addr_t dest, const void *src, size_t len)
{
	(void)flash;
	(void)dest;
	(void)src;
	(void)len;
	return false;
}

//
