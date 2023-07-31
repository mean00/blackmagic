/*
 * This file is part of the Black Magic Debug project.
 *
 * Copyright (C) 2015  Black Sphere Technologies Ltd.
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

/* Exception handling to escape deep nesting.
 * Used for the case of communication failure and timeouts.
 */

/* Example usage:
 *
 * volatile exception_s e;
 * TRY_CATCH (e, EXCEPTION_TIMEOUT) {
 *    ...
 *    raise_exception(EXCEPTION_TIMEOUT, "Timeout occurred");
 *    ...
 * }
 * if (e.type == EXCEPTION_TIMEOUT) {
 *    printf("timeout: %s\n", e.msg);
 * }
 */

/* Limitations:
 * Can't use break, return, goto, etc from inside the TRY_CATCH block.
 */

#ifndef INCLUDE_EXCEPTION_H
#define INCLUDE_EXCEPTION_H

#include <setjmp.h>
#include <stdint.h>

#define EXCEPTION_ERROR   0x01U
#define EXCEPTION_TIMEOUT 0x02U
#define EXCEPTION_ALL     (-1)

typedef struct exception exception_s;

 
// For cortex m0,m0+,m3,m4 without fpu we only have thumb2 (10 registers)
// the compiler will allocate 23 registers which wastes a lof of stack
#ifdef __arm__
    #if defined( __thumb2__ ) && defined(__SOFTFP__) && (__ARM_ARCH==7 || __ARM_ARCH ==6)
      typedef  int BM_JMP[12] ; // it is 10 actually
    #else
      #define BM_JMP jmp_buf
    #endif
#else
  #define BM_JMP jmp_buf
#endif


struct exception {
	uint32_t type;
	const char *msg;
	/* private */
	uint32_t mask;
	BM_JMP jmpbuf;
	exception_s *outer;
};

extern exception_s *innermost_exception;

#define TRY_CATCH(e, type_mask)                   \
	(e).type = 0;                                 \
	(e).mask = (type_mask);                       \
	(e).outer = innermost_exception;              \
	innermost_exception = (struct exception *)&(e);           \
	if (setjmp(innermost_exception->jmpbuf) == 0) \
		for (; innermost_exception == &(e); innermost_exception = (e).outer)

void raise_exception(uint32_t type, const char *msg);

#endif /* INCLUDE_EXCEPTION_H */
