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

#include "general.h"
#include "target.h"
#include "target_internal.h"
#include "cortexm.h"

#if PC_HOSTED == 1
#define debug printf
#else
#define debug(...) \
	{              \
	}
#endif

//#define VERIFY 1

typedef struct {
	uint32_t WS;       // 0
	uint32_t KEYR;     // 4 aka fpec
	uint32_t OBKEYR;   // 8
	uint32_t STATR;    // C
	uint32_t CTLR;     // 10
	uint32_t ADDR;     // 14
	uint32_t filler;   // 18
	uint32_t OBR;      // 1C
	uint32_t WPR;      // 20
	uint32_t MODEKEYR; // 24
} ch32_flash_s;

#define CH32V3XX_FLASH_CONTROLLER_ADDRESS 0x40022000
#define CH32V3XX_UID1                     0x1ffff7e8 // Low bits of UUID
#define CH32V3XX_FMC_CTL_PG               (1 << 0)   // program command
#define CH32V3XX_FMC_CTL_PER              (1 << 1)   // page erase command
#define CH32V3XX_FMC_CTL_START            (1 << 6)
#define CH32V3XX_FMC_CTL_LK               (1 << 7)
#define CH32V3XX_FMC_CTL_CH32_FASTUNLOCK  (1 << 15)
#define CH32V3XX_FMC_CTL_CH32_FASTPROGRAM (1 << 16)
#define CH32V3XX_FMC_CTL_CH32_FASTERASE   (1 << 17)
#define CH32V3XX_FMC_CTL_CH32_FASTSTART   (1 << 21)

#define CH32V3XX_FMC_STAT_BUSY    (1 << 0)
#define CH32V3XX_FMC_STAT_WR_BUSY (1 << 1)
#define CH32V3XX_FMC_STAT_WP_ERR  (1 << 4) // erase / program erro
#define CH32V3XX_FMC_STAT_WP_ENDF (1 << 5) // end of operation
#define CH32V3XX_FMC_STAT_PG_ERR  (1 << 3) // program error
#define CH32V3XX_FMC_STAT_WP_ERR  (1 << 4) // erase / program erro

#define CH32V3XX_KEY1 0x45670123UL
#define CH32V3XX_KEY2 0xcdef89abUL

/* RISC-V targets CH32Vx */
#define CH32VX_CHIPID               0x1ffff704U
#define CH32VX_CHIPID_FAMILY_OFFSET 20U
#define CH32VX_CHIPID_FAMILY_MASK   (0xfffU << CH32VX_CHIPID_FAMILY_OFFSET)

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

/* 
	Identify ch32vxx 
*/
bool ch32v3xx_probe(target_s *target)
{
	int flash_size = 0;
	int ram_size = 0;
	size_t block_size = 256;
	/* CHIPID table
 *	CH32V303CBT6: 0x303305x4
 *	CH32V303RBT6: 0x303205x4
 *	CH32V303RCT6: 0x303105x4
 *	CH32V303VCT6: 0x303005x4
 *	CH32V305FBP6: 0x305205x8
 *	CH32V305RBT6: 0x305005x8
 *	CH32V307WCU6: 0x307305x8
 *	CH32V307FBP6: 0x307205x8
 *	CH32V307RCT6: 0x307105x8
 *	CH32V307VCT6: 0x307005x8
 */

	const uint32_t chipid = target_mem_read32(target, CH32VX_CHIPID);
	switch (chipid & 0xffffff0f) {
	case 0x30330504U: /* CH32V303CBT6 */
	case 0x30320504U: /* CH32V303RBT6 */
	case 0x30310504U: /* CH32V303RCT6 */
	case 0x30300504U: /* CH32V303VCT6 */
	case 0x30520508U: /* CH32V305FBP6 */
	case 0x30500508U: /* CH32V305RBT6 */
	case 0x30730508U: /* CH32V307WCU6 */
	case 0x30720508U: /* CH32V307FBP6 */
	case 0x30710508U: /* CH32V307RCT6 */
	case 0x30700508U: /* CH32V307VCT6 */
		break;
	default:
		return false;
		break;
	}

	DEBUG_WARN("CH32V CHIPID 0x%" PRIx32 " \n", chipid);

	const uint16_t family = (chipid & CH32VX_CHIPID_FAMILY_MASK) >> CH32VX_CHIPID_FAMILY_OFFSET;
	switch (family) {
	case 0x303U:
		target->driver = "CH32V303";
		break;
	case 0x305U:
		target->driver = "CH32V305";
		break;
	case 0x307U:
		target->driver = "CH32V307";
		break;
	default:
		return false;
		break;
	}
	DEBUG_WARN("CH32V family 0x%" PRIx32 " \n", family);

	target->part_id = chipid;

	uint32_t obr = READ_FLASH_REG(target, OBR);
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
	DEBUG_WARN("CH32V flash %d kB, ram %d kB\n", flash_size, ram_size);
	target_add_ram(target, 0x20000000, ram_size * 1024U);
	ch32v3x_add_flash(target, 0x0, (size_t)flash_size * 1024U, block_size);
	target_add_commands(target, ch32v3x_cmd_list, target->driver);

	return true;
}

/*
*/
static bool ch32v3x_fast_unlock(target_s *target)
{
	uint32_t ctl = READ_FLASH_REG(target, CTLR);
	if (!(ctl & CH32V3XX_FMC_CTL_LK)) // already unlocked
		return true;
	// send unlock sequence
	WRITE_FLASH_REG(target, KEYR, CH32V3XX_KEY1);
	WRITE_FLASH_REG(target, KEYR, CH32V3XX_KEY2);

	// send fast unlock sequence
	WRITE_FLASH_REG(target, MODEKEYR, CH32V3XX_KEY1);
	WRITE_FLASH_REG(target, MODEKEYR, CH32V3XX_KEY2);

	uint32_t v = READ_FLASH_REG(target, CTLR);
	return !(v & CH32V3XX_FMC_CTL_CH32_FASTUNLOCK);
}

static void ch32v3x_wait_not_busy(target_flash_s *flash)
{
	// is it busy  ?
	while (1) {
		uint32_t s = READ_FLASH_REG(flash->t, STATR);
		if (!(s & CH32V3XX_FMC_STAT_BUSY))
			return;
	}
}

static void ch32v3x_wait_not_wr_busy(target_flash_s *flash)
{
	// is it wrbusy  ?
	while (1) {
		uint32_t s = READ_FLASH_REG(flash->t, STATR);
		if (!(s & CH32V3XX_FMC_STAT_WR_BUSY))
			return;
	}
}

/*
*/
static void ch32v3x_ctl_set(target_flash_s *flash, uint32_t bits)
{
	uint32_t v = READ_FLASH_REG(flash->t, CTLR);
	v |= bits;
	WRITE_FLASH_REG(flash->t, CTLR, v);
}

/*
*/
static void ch32v3x_ctl_clear(target_flash_s *flash, uint32_t bits)
{
	uint32_t v = READ_FLASH_REG(flash->t, CTLR);
	v &= ~bits;
	WRITE_FLASH_REG(flash->t, CTLR, v);
}

/**
*/
static void ch32v3x_stat_set(target_flash_s *flash, uint32_t bits)
{
	uint32_t v = READ_FLASH_REG(flash->t, STATR);
	v |= bits;
	WRITE_FLASH_REG(flash->t, STATR, v);
}

/**

static void ch32v3x_stat_clear(target_flash_s *flash, uint32_t bits)
{
	uint32_t v = READ_FLASH_REG(flash->t, STATR);
	v &= ~bits;
	WRITE_FLASH_REG(flash->t, STATR, v);
}
*/
/*
*/
#if 0
static bool ch32v3x_fast_lock(target_flash_s *flash)
{
	(void)flash;
	//ch32v3x_ctl_set(flash, CH32V3XX_FMC_CTL_LK);
	return true;
}
#endif
/*
*/
static bool ch32v3x_flash_erase(target_flash_s *flash, target_addr_t addr, size_t len)
{
	//(void)flash;
	(void)addr;
	(void)len;
	ch32v3x_fast_unlock(flash->t);

	uint32_t cur_addr = addr;
	cur_addr += 0x08000000; // some leftover from older chip it seems
	uint32_t end_addr = cur_addr + len;
	while (cur_addr < end_addr) {
		ch32v3x_ctl_set(flash, CH32V3XX_FMC_CTL_CH32_FASTERASE);
		WRITE_FLASH_REG(flash->t, ADDR, cur_addr);
		ch32v3x_ctl_set(flash, CH32V3XX_FMC_CTL_START);
		ch32v3x_wait_not_busy(flash);
		//ch32v3x_stat_set(flash, CH32V3XX_FMC_STAT_WP_ENDF); // clear end of process bit
		ch32v3x_ctl_clear(flash, CH32V3XX_FMC_CTL_CH32_FASTERASE);
#ifdef VERIFY
		uint32_t a;
		for (a = 0; a < 256; a += 4) {
			uint32_t s = target_mem_read32(flash->t, cur_addr + a);
			if (s != 0xe339e339UL) //the wch does not fill the flash with ff !
			{
				printf("******Bad erase at address %x\n", cur_addr + a);
				ch32v3x_fast_lock(flash);
				return false;
			}
		}
#endif
		cur_addr += 256;
	}
	//ch32v3x_fast_lock(flash);
	return true;
}

/*
*/
static bool ch32v3x_flash_write(target_flash_s *flash, target_addr_t dest, const void *srcx, size_t len)
{
	uint32_t cur_addr = dest;
	const uint8_t *src = (const uint8_t *)srcx;
	// Warning : it is assumed address is 8 bytes aligned TODO TODO
	cur_addr += 0x08000000; // some leftover from older chip it seems

	uint32_t end_addr = cur_addr + len;
	while (cur_addr < end_addr) {
		ch32v3x_ctl_set(flash, CH32V3XX_FMC_CTL_CH32_FASTPROGRAM);
		ch32v3x_wait_not_busy(flash);
		// prefill write cache, we write 256 bytes at a time
		for (int i = 0; i < 64; i++) {
			uint32_t data32 = (src[0]) + (src[1] << 8) + (src[2] << 16) + (src[3] << 24);
			target_mem_write32(flash->t, cur_addr, data32);
			src += 4;
			cur_addr += 4;
			ch32v3x_wait_not_wr_busy(flash);
		}
		// and flush
		ch32v3x_ctl_set(flash, CH32V3XX_FMC_CTL_CH32_FASTSTART); // and go
		ch32v3x_wait_not_busy(flash);

		ch32v3x_ctl_clear(flash, CH32V3XX_FMC_CTL_PG); // done
		uint32_t stat = READ_FLASH_REG(flash->t, STATR);
		if (stat & (CH32V3XX_FMC_STAT_PG_ERR + CH32V3XX_FMC_STAT_WP_ERR)) {
			ch32v3x_stat_set(flash, CH32V3XX_FMC_STAT_PG_ERR + CH32V3XX_FMC_STAT_WP_ERR); // clear error
			debug("Write error at offset 0x%x", cur_addr);
			return false;
		}
		ch32v3x_stat_set(flash, CH32V3XX_FMC_STAT_WP_ENDF); // done tODO TODO
		if (!(stat & CH32V3XX_FMC_STAT_WP_ENDF)) {
			debug("Write error 2 at offset 0x%x", cur_addr);
			return false;
		}
	}
	//
	return true;
}

//
