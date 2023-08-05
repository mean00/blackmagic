CC=/riscv/tools_llvm/bin/clang-17
OBJDUMP=/riscv/tools_llvm/bin/llvm-objcopy
rm -f ch32c3x_erase.o
set -x
$CC ch32vx_erase.c -g -c -O2 -o ch32v3x_erase.o
$OBJDUMP -Obinary ch32v3x_erase.o ch32v3x_erase.bin
xxd -i ch32v3x_erase.bin >ch32v3x_erase.h
