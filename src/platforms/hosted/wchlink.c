/*
 * This file is part of the Black Magic Debug project.
 *
 * Copyright (C) 2022 1BitSquared <info@1bitsquared.com>
 * Written by Rafael Silva <perigoso@riseup.net>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

	The general query format is
	0x81 GROUP COMMAND PAYLOADSIZE [payload...]
	the general reply is
	0x82 GROUP COMMAND

	Wchlink is using EP1 for control
	and EP2 for data transfer (ram content, flash content)

 */

#include <libusb.h>

#include "wchlink.h"

#include "riscv_debug.h"
#include "riscv_dtm_wchlink.h"

#if 1
#define debug printf
#else
#define debug(...) \
	{              \
	}
#endif

#define WCHLINK_CONTROL_ENDPOINT 0x1U
#define WCHLINK_DATA_ENDPOINT    0x2U

#define TRANSFER_TIMEOUT_MS 500U

#define WCH_CMD_OUT_HEADER 0x81U
#define WCH_CMD_IN_HEADER  0x82U

/*
	Program group
*/
#define WCH_PROGRAM_GRP 0x02U

typedef enum wch_prog_command {
	WCH_PROGRAM_ERASE_FLASH = 0x01,
	WCH_PROGRAM_BEGIN_WRITE_FLASH = 0x02,
	WCH_PROGRAM_BEGIN_RAM_TRANSFER = 0x05,
	WCH_PROGRAM_PREPARE = 0x06,
	WCH_PROGRAM_EXEC_RAM = 0x07,
	WCH_PROGRAM_END = 0x08,
	WCH_PROGRAM_END_RAM_TRANSFER = 0x09,
} wch_prog_command_t;

/* Flash protection commands */
#define WCH_PROTECT_GRP 0x06U

typedef enum wch_protect_command {
	WCH_PROTECT_QUERY = 0x01,
	WCH_PROTECT_QUERYV2 = 0x04,
	WCH_PROTECT_PROTECT = 0x03,
	WCH_PROTECT_PROTECTV2 = 0xf3,
	WCH_PROTECT_UNPROTECT = 0x02,
	WCH_PROTECT_UNPROTECTV2 = 0xf2,
} wch_protect_command_t;

/* DMI access commands */
#define WCH_DMI_GRP 0x08U

typedef enum wch_dmi_command {
	WCH_DMI_CMD_NOP = 0x00,
	WCH_DMI_CMD_READ = 0x01,
	WCH_DMI_CMD_WRITE = 0x02,
} wch_dmi_command_t;

/* System commands */
#define WCH_SYS_GRP 0x0dU

typedef enum wch_sys_command {
	WCH_SYS_CMD_GET_VERSION = 0x01,
	WCH_SYS_CMD_CONNECT = 0x02,
	WCH_SYS_CMD_UNKNOWN = 0x03,
	WCH_SYS_CMD_GET_MEMINFO = 0x04,
	WCH_SYS_CMD_CLOSE = 0xff,

} wch_sys_command_t;

/* Debug commands */
#define WCH_DBG_GRP             0x0eU
#define WCH_DBG_CMD_DISABLE_DBG 0x01U

/* Error ? who knows */
#define WCH_ERR_GRP 0x55U

static bool wchlink_exchange(const char *what, uint32_t len, const uint8_t *data, int reply_size, uint8_t *reply);
static bool wchlink_exchange4(const char *what, uint32_t len, const uint8_t *data);

static bool wchlink_bulk_write_g(bmp_info_s *const info, int endpoint, const uint8_t *const data, const size_t length)
{
	int transferred = 0;
	const int result = libusb_bulk_transfer(
		info->usb_link->device_handle, endpoint, (unsigned char *)data, length, &transferred, TRANSFER_TIMEOUT_MS);
	if (result < 0) {
		DEBUG_WARN("WCH-Link write error: %s (%d)\n", libusb_strerror(result), result);
		return false;
	}

	return true;
}

static bool wchlink_bulk_write(bmp_info_s *const info, const uint8_t *const data, const size_t length)
{
	return wchlink_bulk_write_g(info, WCHLINK_CONTROL_ENDPOINT, data, length);
}

static bool wchlink_bulk_write2(bmp_info_s *const info, const uint8_t *const data, const size_t length)
{
	return wchlink_bulk_write_g(info, WCHLINK_DATA_ENDPOINT, data, length);
}

static bool wchlink_bulk_read_g(bmp_info_s *const info, int endpoint, uint8_t *const data, const size_t length)
{
	int transferred = 0;
	const int result =
		libusb_bulk_transfer(info->usb_link->device_handle, endpoint, data, length, &transferred, TRANSFER_TIMEOUT_MS);
	if (result < 0) {
		DEBUG_WARN("WCH-Link read error: %s (%d)\n", libusb_strerror(result), result);
		return false;
	}
	if (length != transferred) {
		DEBUG_WARN("WCH-Link read mismatch: %d (%zu expected)\n", transferred, length);
	}
	return true;
}

static bool wchlink_bulk_read(bmp_info_s *const info, uint8_t *const data, const size_t length)
{
	return wchlink_bulk_read_g(info, 0x80 | WCHLINK_CONTROL_ENDPOINT, data, length);
}

static bool wchlink_bulk_read2(bmp_info_s *const info, uint8_t *const data, const size_t length)
{
	return wchlink_bulk_read_g(info, 0x80 | WCHLINK_DATA_ENDPOINT, data, length);
}

/*
 * On success this copies the endpoint addresses identified into the
 * usb_link_s sub-structure of bmp_info_s (info->usb_link) for later use.
 * Returns true for success, false for failure.
 */
static bool claim_wchlink_interface(bmp_info_s *info, libusb_device *dev)
{
	libusb_config_descriptor_s *config;
	const int result = libusb_get_active_config_descriptor(dev, &config);
	if (result != LIBUSB_SUCCESS) {
		DEBUG_WARN("Failed to get configuration descriptor: %s\n", libusb_error_name(result));
		return false;
	}

	const libusb_interface_descriptor_s *descriptor = NULL;
	for (size_t i = 0; i < config->bNumInterfaces; ++i) {
		const libusb_interface_s *const interface = &config->interface[i];
		const libusb_interface_descriptor_s *const interface_desc = &interface->altsetting[0];
		if (interface_desc->bInterfaceClass == LIBUSB_CLASS_VENDOR_SPEC && interface_desc->bInterfaceSubClass == 128U) {
			const int result = libusb_claim_interface(info->usb_link->device_handle, i);
			if (result) {
				DEBUG_WARN("Can not claim handle: %s\n", libusb_error_name(result));
				break;
			}

			info->usb_link->interface = i;
			descriptor = interface_desc;
		}
	}
	if (!descriptor) {
		DEBUG_WARN("No suitable interface found\n");
		libusb_free_config_descriptor(config);
		return false;
	}

	for (size_t i = 0; i < descriptor->bNumEndpoints; i++) {
		const libusb_endpoint_descriptor_s *endpoint = &descriptor->endpoint[i];

		if ((endpoint->bEndpointAddress & LIBUSB_ENDPOINT_ADDRESS_MASK) == WCHLINK_CONTROL_ENDPOINT) {
			if (endpoint->bEndpointAddress & LIBUSB_ENDPOINT_DIR_MASK)
				info->usb_link->ep_rx = endpoint->bEndpointAddress;
			else
				info->usb_link->ep_tx = endpoint->bEndpointAddress;
		}
	}
	libusb_free_config_descriptor(config);
	return true;
}

/*

*/
bool wchlink_exchange(const char *what, uint32_t len, const uint8_t *data, int reply_size, uint8_t *reply)
{
	if (reply_size < 7) {
		debug("Query:");
		for (int i = 0; i < len; i++)
			debug("%02x ", data[i]);
		debug("\n");
	}

	if (!wchlink_bulk_write(&info, data, len)) {
		debug("write %s failed\n", what);
		return false;
	}

	bool r = wchlink_bulk_read(&info, reply, reply_size);

	if (reply_size < 7) {
		debug("Reply:");
		for (int i = 0; i < reply_size; i++)
			debug("%02x ", reply[i]);
		debug("\n");
	}

	if (!r) {
		debug("write %s reply failed\n", what);
		return false;
	}
	return true;
}

/*
*/
static bool wchlink_exchange4(const char *what, uint32_t len, const uint8_t *data)
{
	uint8_t reply[4];
	return wchlink_exchange(what, len, data, sizeof(reply), reply);
}

/*
*/
static bool wchlink_read_version(bmp_info_s *info)
{
	uint8_t cmd[] = {
		WCH_CMD_OUT_HEADER,
		WCH_SYS_GRP,
		1, // size of payload
		WCH_SYS_CMD_GET_VERSION,
	};
	if (!wchlink_bulk_write(info, cmd, sizeof(cmd)))
		return false;

	uint8_t response[7];
	if (!wchlink_bulk_read(info, response, sizeof(response)))
		return false;

	const uint8_t wchlink_major = response[3];
	const uint8_t wchlink_minor = response[4];
	const uint8_t wchlink_id = response[5];

	const char *wchlink_name = NULL;
	switch (wchlink_id) {
	case 1:
		wchlink_name = "WCH-Link-CH549 (RV)";
		break;
	case 2:
		wchlink_name = "WCH-LinkE-CH32V307 (RV)";
		break;
	case 3:
		wchlink_name = "WCH-LinkS-CH32V203 (RV)";
		break;
	case 4:
		wchlink_name = "WCH-LinkB (RV)";
		break;
	default:
		wchlink_name = "unknow WCH-LINK";
		break;
	}

	DEBUG_INFO("%s (id:%u) v%u.%u\n", wchlink_name, wchlink_id, wchlink_major, wchlink_minor);

	return true;
}

/*
*/
static bool wchlink_connect(bmp_info_s *info, uint8_t *const device_code, uint32_t *const device_id)
{
	const uint8_t cmd[] = {
		WCH_CMD_OUT_HEADER,
		WCH_SYS_GRP,
		1, // size of payload
		WCH_SYS_CMD_CONNECT,
	};

	uint8_t reply[8];
	if (!wchlink_exchange("cnx", sizeof(cmd), cmd, sizeof(reply), reply))
		return false;

	if (reply[1] != WCH_SYS_GRP) { // response[1] returns WCH_ERR_GRP (0x55) on error
		DEBUG_WARN("WCH-Link failed to connect with device\n");
		return false;
	}

	*device_code = reply[3];
	*device_id = (reply[4] << 24U) + (reply[5] << 16U) + (reply[6] << 8U) + (reply[7] & 0x0fU);

	return true;
}

/*
*/
static bool wchlink_unknown(bmp_info_s *info)
{
	const uint8_t cmd[] = {
		WCH_CMD_OUT_HEADER,
		WCH_SYS_GRP,
		1, // size of payload
		WCH_SYS_CMD_UNKNOWN,
	};

	return wchlink_exchange4("unknown", sizeof(cmd), cmd);
}

/*
*/
bool wchlink_riscv_dmi_write(bmp_info_s *info, const uint32_t address, const uint32_t value)
{
	const uint8_t cmd[] = {
		WCH_CMD_OUT_HEADER,
		WCH_DMI_GRP,
		6, // payload size , 6 bytes
		address & 0xffU,
		value >> 24U,
		value >> 16U,
		value >> 8U,
		value & 0xffU,
		WCH_DMI_CMD_WRITE,
	};
	uint8_t reply[9];
	if (!wchlink_exchange("dmiwr", sizeof(cmd), cmd, sizeof(reply), reply))
		return false;
	if (reply[8]) { /* status */
		debug("Error reply 0x%x\n", reply[8]);
		return false;
	}
	return true;
}

/*
*/
bool wchlink_riscv_dmi_read(bmp_info_s *info, const uint32_t address, uint32_t *const value)
{
	const uint8_t cmd[] = {
		WCH_CMD_OUT_HEADER,
		WCH_DMI_GRP,
		6, // size of payload,
		address & 0xffU,
		0U,
		0U,
		0U,
		0U,
		WCH_DMI_CMD_READ,
	};
	uint8_t reply[9];
	if (!wchlink_exchange("dmird", sizeof(cmd), cmd, sizeof(reply), reply))
		return false;

	if (reply[8]) { /* status */
		debug("WCH-Link failed to read DMI register\n");
		return false;
	}
	*value = (reply[4] << 24U) + (reply[5] << 16U) + (reply[6] << 8U) + reply[7];
	return true;
}

/*
*/
bool wchlink_init(bmp_info_s *const info)
{
	usb_link_s *link = calloc(1, sizeof(usb_link_s));
	if (!link)
		return false;
	info->usb_link = link;
	link->context = info->libusb_ctx;

	libusb_device **device_list = NULL;
	const ssize_t device_count = libusb_get_device_list(info->libusb_ctx, &device_list);
	if (device_count < 0) {
		DEBUG_WARN("libusb_get_device_list() failed");
		return false;
	}

	libusb_device *device_wchlink = NULL;
	for (ssize_t device_index = 0; device_index < device_count; ++device_index) {
		if (!device_list[device_index])
			continue;

		libusb_device *const device = device_list[device_index];
		struct libusb_device_descriptor device_descriptor;
		if (libusb_get_device_descriptor(device, &device_descriptor) < 0) {
			DEBUG_WARN("libusb_get_device_descriptor() failed");
			libusb_free_device_list(device_list, 1);
			return false;
		}

		if (device_descriptor.idVendor != info->vid || device_descriptor.idProduct != info->pid)
			continue;

		int result = libusb_open(device, &link->device_handle);
		if (result != LIBUSB_SUCCESS)
			continue;

		device_wchlink = device;
		break;
	}

	if (!device_wchlink || !claim_wchlink_interface(info, device_wchlink)) {
		libusb_free_device_list(device_list, 1);
		return false;
	}

	if (!link->ep_tx || !link->ep_rx) {
		DEBUG_WARN("Device setup failed\n");
		libusb_release_interface(info->usb_link->device_handle, info->usb_link->interface);
		libusb_close(info->usb_link->device_handle);
		libusb_free_device_list(device_list, 1);
		return false;
	}

	libusb_free_device_list(device_list, 1);

	return wchlink_read_version(info);
}

/*
*/
const char *wchlink_target_voltage(bmp_info_s *info)
{
	(void)info;
	return "Unavailable";
}

/*
*/
void wchlink_nrst_set_val(bmp_info_s *info, bool assert)
{
	(void)info;
	(void)assert;
}

/*
*/
bool wchlink_nrst_get_val(bmp_info_s *info)
{
	(void)info;
	return true;
}

/*
*/
uint32_t wchlink_rvswd_scan(bmp_info_s *info)
{
	(void)info;

	target_list_free();

	uint8_t device_code;
	uint32_t device_id;

	if (!wchlink_connect(info, &device_code, &device_id)) {
		DEBUG_WARN("WCH-Link failed to connect to target");
		return 0U;
	}

	DEBUG_WARN("WCH-Link connected with 0x%0X\n", device_id);

	switch (device_code) {
	case 0x1U:
	case 0x5U:
	case 0x6U:
	case 0x9U:
	case 0xaU:
		wchlink_unknown(info);
		break;

	default:
		break;
	}

	return riscv_dtm_wchlink_handler();
}

/*

*/
bool wch_simple_programm_command(wch_prog_command_t cmd)
{
	const uint8_t tx[] = {WCH_CMD_OUT_HEADER, WCH_PROGRAM_GRP, 0x01, cmd};
	if (!wchlink_exchange4("", sizeof(tx), tx))
		return false;
	return true;
}

#define CHECK_CMD(x)                       \
	if (!wch_simple_programm_command(x)) { \
		debug(#x " failed\n");             \
		return false;                      \
	}                                      \
	debug(#x " ok\n");

/*
	Write data at the beginning of the ram
	It is fast but for some reasons only works once
*/
bool wchlink_ram_write(bmp_info_s *info, const uint32_t xaddress, const uint32_t xlen, const uint8_t *data)
{
	uint32_t len = xlen;
	uint32_t address = 0x08000000UL;

	// configure using the control endpoint
	CHECK_CMD(WCH_PROGRAM_PREPARE);
#if 1
	const uint8_t set_window[] = {WCH_CMD_OUT_HEADER, 0x01,
		0x08, // len
		(uint8_t)(address >> 24), (uint8_t)(address >> 16), (uint8_t)(address >> 8), (uint8_t)(address >> 0), 0xff,
		0xff, 0xff, 0xff};
	if (!wchlink_exchange4("", sizeof(set_window), set_window)) {
		debug("set window failed\n");
		return false;
	}
#endif
	CHECK_CMD(WCH_PROGRAM_BEGIN_RAM_TRANSFER);
	// send 64 bytes chunks on the data endpoint
	while (len) {
		uint32_t c = len;
		if (c > 64)
			c = 64;
		len -= c;
		if (!wchlink_bulk_write2(info, data, c)) {
			debug("Data send failed\n");
			return false;
		}
		data += c;
	}
	//uint8_t reply[4];
	//if(!wchlink_bulk_read2(info,  reply, sizeof(reply)))
	//{
	//	debug("end of write ram\n");
	//}
	//CHECK_CMD(WCH_PROGRAM_EXEC_RAM);
	CHECK_CMD(WCH_PROGRAM_BEGIN_WRITE_FLASH);
	CHECK_CMD(WCH_PROGRAM_END);
	return true;
}

//EOF
