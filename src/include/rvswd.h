/*
 * This file is part of the Black Magic Debug project.
 *
 * Copyright (C) 2011  Black Sphere Technologies Ltd.
 * Written by Gareth McMullin <gareth@blacksphere.co.nz>
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

#ifndef INCLUDE_RVSWD_H
#define INCLUDE_RVSWD_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Functions interface talking RVSWD */
typedef struct rvswd_proc {
	bool (*read)(const uint32_t adress, uint32_t *data);
	bool (*write)(const uint32_t adress, const uint32_t data);
} rvswd_proc_s;

extern rvswd_proc_s rvswd_proc;

void rvswdptap_init(void);
struct bmp_info_s;
uint32_t rvswd_scan();

#endif /*INCLUDE_RVSWD_H*/

