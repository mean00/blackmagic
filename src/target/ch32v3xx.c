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
#include "jep106.h"

//static bool ch32v3x_cmd_option(target_s *target, int argc, const char **argv);

const command_s ch32v3x_cmd_list[] = {
	{NULL, NULL, NULL},
};

static bool ch32v3x_flash_erase(target_flash_s *flash, target_addr_t addr, size_t len);
static bool ch32v3x_flash_write(target_flash_s *flash, target_addr_t dest, const void *src, size_t len);

//static bool ch32v3x_mass_erase(target_s *target);

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

static uint16_t ch32v3x_read_idcode(target_s *const target)
{
	(void)target;
	//		return target_mem_read32(target, DBGMCU_IDCODE_F0) & 0xfffU;
	return 0;
}

/* Identify ch32v3x */
bool ch32v3xx_probe(target_s *target)
{
	const uint16_t device_id = ch32v3x_read_idcode(target);
	size_t block_size = 0x400;

	switch (device_id) {
	case 0x000U: /* Gigadevice gd32f303 */
		target->driver = "CH32V3XX";
		break;
	default:
		return false;
	}
#if 0
	const uint32_t signature = target_mem_read32(target, GD32Fx_FLASHSIZE);
	const uint16_t flash_size = signature & 0xffffU;
	const uint16_t ram_size = signature >> 16U;

	target->part_id = device_id;
	target->mass_erase = ch32v3x_mass_erase;
#endif
	int ram_size = 64;
	int flash_size = 256;
	target_add_ram(target, 0x20000000, ram_size * 1024U);
	ch32v3x_add_flash(target, 0x0, (size_t)flash_size * 1024U, block_size);
	target_add_commands(target, ch32v3x_cmd_list, target->driver);

	return true;
}

static bool ch32v3x_flash_erase(target_flash_s *flash, target_addr_t addr, size_t len)
{
	(void)flash;
	(void)addr;
	(void)len;
	return false;
}

static bool ch32v3x_flash_write(target_flash_s *flash, target_addr_t dest, const void *src, size_t len)
{
	(void)flash;
	(void)dest;
	(void)src;
	(void)len;
	return false;
}
#if 0
static bool ch32v3x_mass_erase(target_s *target)
{
    (void)target;
    return false;
}
#endif
#if 0
static bool ch32v3x_flash_unlock(target_s *target, uint32_t bank_offset)
{
	target_mem_write32(target, FLASH_KEYR + bank_offset, KEY1);
	target_mem_write32(target, FLASH_KEYR + bank_offset, KEY2);
	uint32_t ctrl = target_mem_read32(target, FLASH_CR);
	if (ctrl & FLASH_CR_LOCK)
		DEBUG_ERROR("unlock failed, cr: 0x%08" PRIx32 "\n", ctrl);
	return !(ctrl & FLASH_CR_LOCK);
}

static inline void ch32v3x_flash_clear_eop(target_s *const target, const uint32_t bank_offset)
{
	const uint32_t status = target_mem_read32(target, FLASH_SR + bank_offset);
	target_mem_write32(target, FLASH_SR + bank_offset, status | SR_EOP); /* EOP is W1C */
}

static bool ch32v3x_flash_busy_wait(
	target_s *const target, const uint32_t bank_offset, platform_timeout_s *const timeout)
{
	/* Read FLASH_SR to poll for BSY bit */
	uint32_t status = FLASH_SR_BSY;
	/*
	 * Please note that checking EOP here is only legal because every operation is preceded by
	 * a call to ch32v3x_flash_clear_eop. Without this the flag could be stale from a previous
	 * operation and is always set at the end of every program/erase operation.
	 * For more information, see FLASH_SR register description §3.4 pg 25.
	 * https://www.st.com/resource/en/programming_manual/pm0075-ch32v3x0xxx-flash-memory-microcontrollers-stmicroelectronics.pdf
	 */
	while (!(status & SR_EOP) && (status & FLASH_SR_BSY)) {
		status = target_mem_read32(target, FLASH_SR + bank_offset);
		if (target_check_error(target)) {
			DEBUG_ERROR("Lost communications with target");
			return false;
		}
		if (timeout)
			target_print_progress(timeout);
	};
	if (status & SR_ERROR_MASK)
		DEBUG_ERROR("ch32v3x flash error 0x%" PRIx32 "\n", status);
	return !(status & SR_ERROR_MASK);
}

static uint32_t ch32v3x_bank_offset_for(target_addr_t addr)
{
	if (addr >= FLASH_BANK_SPLIT)
		return FLASH_BANK2_OFFSET;
	return FLASH_BANK1_OFFSET;
}

static bool ch32v3x_flash_erase(target_flash_s *flash, target_addr_t addr, size_t len)
{
	target_s *target = flash->t;
	target_addr_t end = addr + len - 1U;

	/* Unlocked an appropriate flash bank */
	if ((target->part_id == 0x430U && end >= FLASH_BANK_SPLIT && !ch32v3x_flash_unlock(target, FLASH_BANK2_OFFSET)) ||
		(addr < FLASH_BANK_SPLIT && !ch32v3x_flash_unlock(target, 0)))
		return false;

	for (size_t offset = 0; offset < len; offset += flash->blocksize) {
		const uint32_t bank_offset = ch32v3x_bank_offset_for(addr + offset);
		ch32v3x_flash_clear_eop(target, bank_offset);

		/* Flash page erase instruction */
		target_mem_write32(target, FLASH_CR + bank_offset, FLASH_CR_PER);
		/* write address to FMA */
		target_mem_write32(target, FLASH_AR + bank_offset, addr + offset);
		/* Flash page erase start instruction */
		target_mem_write32(target, FLASH_CR + bank_offset, FLASH_CR_STRT | FLASH_CR_PER);

		/* Wait for completion or an error */
		if (!ch32v3x_flash_busy_wait(target, bank_offset, NULL))
			return false;
	}
	return true;
}

static size_t ch32v3x_bank1_length(target_addr_t addr, size_t len)
{
	if (addr >= FLASH_BANK_SPLIT)
		return 0;
	if (addr + len > FLASH_BANK_SPLIT)
		return FLASH_BANK_SPLIT - addr;
	return len;
}

static bool ch32v3x_flash_write(target_flash_s *flash, target_addr_t dest, const void *src, size_t len)
{
	target_s *target = flash->t;
	const size_t offset = ch32v3x_bank1_length(dest, len);

	/* Start by writing any bank 1 data */
	if (offset) {
		ch32v3x_flash_clear_eop(target, FLASH_BANK1_OFFSET);

		target_mem_write32(target, FLASH_CR, FLASH_CR_PG);
		/* Use the target API instead of a direct Cortex-M call for GD32VF103 parts */
		if (target->designer_code == JEP106_MANUFACTURER_RV_GIGADEVICE && target->cpuid == 0x80000022U)
			target_mem_write(target, dest, src, offset);
		else
			cortexm_mem_write_sized(target, dest, src, offset, ALIGN_HALFWORD);

		/* Wait for completion or an error */
		if (!ch32v3x_flash_busy_wait(target, FLASH_BANK1_OFFSET, NULL))
			return false;
	}

	/* If there's anything to write left over and we're on a part with a second bank, write to bank 2 */
	const size_t remainder = len - offset;
	if (target->part_id == 0x430U && remainder) {
		const uint8_t *data = src;
		ch32v3x_flash_clear_eop(target, FLASH_BANK2_OFFSET);

		target_mem_write32(target, FLASH_CR + FLASH_BANK2_OFFSET, FLASH_CR_PG);
		/* Use the target API instead of a direct Cortex-M call for GD32VF103 parts */
		if (target->designer_code == JEP106_MANUFACTURER_RV_GIGADEVICE && target->cpuid == 0x80000022U)
			target_mem_write(target, dest + offset, data + offset, remainder);
		else
			cortexm_mem_write_sized(target, dest + offset, data + offset, remainder, ALIGN_HALFWORD);

		/* Wait for completion or an error */
		if (!ch32v3x_flash_busy_wait(target, FLASH_BANK2_OFFSET, NULL))
			return false;
	}

	return true;
}

static bool ch32v3x_mass_erase_bank(
	target_s *const target, const uint32_t bank_offset, platform_timeout_s *const timeout)
{
	/* Unlock the bank */
	if (!ch32v3x_flash_unlock(target, bank_offset))
		return false;
	ch32v3x_flash_clear_eop(target, bank_offset);

	/* Flash mass erase start instruction */
	target_mem_write32(target, FLASH_CR + bank_offset, FLASH_CR_MER);
	target_mem_write32(target, FLASH_CR + bank_offset, FLASH_CR_STRT | FLASH_CR_MER);

	/* Wait for completion or an error */
	return ch32v3x_flash_busy_wait(target, bank_offset, timeout);
}

static bool ch32v3x_mass_erase(target_s *target)
{
	if (!ch32v3x_flash_unlock(target, 0))
		return false;

	platform_timeout_s timeout;
	platform_timeout_set(&timeout, 500);
	if (!ch32v3x_mass_erase_bank(target, FLASH_BANK1_OFFSET, &timeout))
		return false;

	/* If we're on a part that has a second bank, mass erase that bank too */
	if (target->part_id == 0x430U)
		return ch32v3x_mass_erase_bank(target, FLASH_BANK2_OFFSET, &timeout);
	return true;
}

static uint16_t ch32v3x_flash_readable_key(const target_s *const target)
{
	switch (target->part_id) {
	case 0x422U: /* STM32F30x */
	case 0x432U: /* STM32F37x */
	case 0x438U: /* STM32F303x6/8 and STM32F328 */
	case 0x440U: /* STM32F0 */
	case 0x446U: /* STM32F303xD/E and STM32F398xE */
	case 0x445U: /* STM32F04 RM0091 Rev.7, STM32F070x6 RM0360 Rev. 4*/
	case 0x448U: /* STM32F07 RM0091 Rev.7, STM32F070xb RM0360 Rev. 4*/
	case 0x442U: /* STM32F09 RM0091 Rev.7, STM32F030xc RM0360 Rev. 4*/
		return FLASH_OBP_RDP_KEY_F3;
	}
	return FLASH_OBP_RDP_KEY;
}

static bool ch32v3x_option_erase(target_s *target)
{
	ch32v3x_flash_clear_eop(target, FLASH_BANK1_OFFSET);

	/* Erase option bytes instruction */
	target_mem_write32(target, FLASH_CR, FLASH_CR_OPTER | FLASH_CR_OPTWRE);
	target_mem_write32(target, FLASH_CR, FLASH_CR_STRT | FLASH_CR_OPTER | FLASH_CR_OPTWRE);

	/* Wait for completion or an error */
	return ch32v3x_flash_busy_wait(target, FLASH_BANK1_OFFSET, NULL);
}

static bool ch32v3x_option_write_erased(
	target_s *const target, const size_t offset, const uint16_t value, const bool write16_broken)
{
	if (value == 0xffffU)
		return true;

	ch32v3x_flash_clear_eop(target, FLASH_BANK1_OFFSET);

	/* Erase option bytes instruction */
	target_mem_write32(target, FLASH_CR, FLASH_CR_OPTPG | FLASH_CR_OPTWRE);

	const uint32_t addr = FLASH_OBP_RDP + (offset * 2U);
	if (write16_broken)
		target_mem_write32(target, addr, 0xffff0000U | value);
	else
		target_mem_write16(target, addr, value);

	/* Wait for completion or an error */
	const bool result = ch32v3x_flash_busy_wait(target, FLASH_BANK1_OFFSET, NULL);
	if (result || offset != 0U)
		return result;
	/*
	 * In the case that the write failed and we're handling option byte 0 (RDP),
	 * check if we got a status of "Program Error" in FLASH_SR, indicating the target
	 * refused to erase the read protection option bytes (and turn it into a truthy return).
	 */
	const uint8_t status = target_mem_read32(target, FLASH_SR) & SR_ERROR_MASK;
	return status == SR_PROG_ERROR;
}

static bool ch32v3x_option_write(target_s *const target, const uint32_t addr, const uint16_t value)
{
	const uint32_t index = (addr - FLASH_OBP_RDP) >> 1U;
	/* If index would be negative, the high most bit is set, so we get a giant positive number. */
	if (index > 7U)
		return false;

	uint16_t opt_val[8];
	/* Retrieve old values */
	for (size_t i = 0U; i < 16U; i += 4U) {
		const size_t offset = i >> 1U;
		uint32_t val = target_mem_read32(target, FLASH_OBP_RDP + i);
		opt_val[offset] = val & 0xffffU;
		opt_val[offset + 1U] = val >> 16U;
	}

	if (opt_val[index] == value)
		return true;

	/* Check for erased value */
	if (opt_val[index] != 0xffffU && !ch32v3x_option_erase(target))
		return false;
	opt_val[index] = value;

	/*
	 * Write changed values, taking into account if we can use 32- or have to use 16-bit writes.
	 * GD32E230 is a special case as target_mem_write16 does not work
	 */
	const bool write16_broken = target->part_id == 0x410U && (target->cpuid & CPUID_PARTNO_MASK) == CORTEX_M23;
	for (size_t i = 0U; i < 8U; ++i) {
		if (!ch32v3x_option_write_erased(target, i, opt_val[i], write16_broken))
			return false;
	}

	return true;
}

static bool ch32v3x_cmd_option(target_s *target, int argc, const char **argv)
{
	const uint32_t read_protected = target_mem_read32(target, FLASH_OBR) & FLASH_OBR_RDPRT;
	const bool erase_requested = argc == 2 && strcmp(argv[1], "erase") == 0;
	/* Fast-exit if the Flash is not readable and the user didn't ask us to erase the option bytes */
	if (read_protected && !erase_requested) {
		tc_printf(target, "Device is Read Protected\nUse `monitor option erase` to unprotect and erase device\n");
		return true;
	}

	/* Unprotect the option bytes so we can modify them */
	if (!ch32v3x_flash_unlock(target, FLASH_BANK1_OFFSET))
		return false;
	target_mem_write32(target, FLASH_OPTKEYR, KEY1);
	target_mem_write32(target, FLASH_OPTKEYR, KEY2);

	if (erase_requested) {
		/* When the user asks us to erase the option bytes, kick of an erase */
		if (!ch32v3x_option_erase(target))
			return false;
		/*
		 * Write the option bytes Flash readable key, taking into account if we can
		 * use 32- or have to use 16-bit writes.
		 * GD32E230 is a special case as target_mem_write16 does not work
		 */
		const bool write16_broken = target->part_id == 0x410U && (target->cpuid & CPUID_PARTNO_MASK) == CORTEX_M23;
		if (!ch32v3x_option_write_erased(target, 0U, ch32v3x_flash_readable_key(target), write16_broken))
			return false;
	} else if (argc == 3) {
		/* If 3 arguments are given, assume the second is an address, and the third a value */
		const uint32_t addr = strtoul(argv[1], NULL, 0);
		const uint32_t val = strtoul(argv[2], NULL, 0);
		/* Try and program the new option value to the requested option byte */
		if (!ch32v3x_option_write(target, addr, val))
			return false;
	} else
		tc_printf(target, "usage: monitor option erase\nusage: monitor option <addr> <value>\n");

	/* When all gets said and done, display the current option bytes values */
	for (size_t i = 0U; i < 16U; i += 4U) {
		const uint32_t addr = FLASH_OBP_RDP + i;
		const uint32_t val = target_mem_read32(target, addr);
		tc_printf(target, "0x%08X: 0x%04X\n", addr, val & 0xffffU);
		tc_printf(target, "0x%08X: 0x%04X\n", addr + 2U, val >> 16U);
	}

	return true;
}
#endif
