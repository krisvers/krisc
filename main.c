#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "types.h"

typedef struct cpu {
	union {
		struct {
			u32 ra;
			u32 rb;
			u32 rc;
			u32 rd;
			u32 re;
			u32 rf;
			u32 rg;
			u32 rh;

			u32 sp;
			u32 bp;
			u32 ip;
		};
		u32 regs[11];
	};

	u32 int_lookup;

	struct {
		u32 size;
		u8 * pointer;
	} memory;

	b8 halt;
} cpu_t;

typedef void (*handler_t)();

cpu_t cpu;
handler_t instructions[0x14];

/* fetchers */
u8 fetch_opcode();
u8 fetch_modifier();
u8 fetch_operand_byte(u16 byte);
u16 fetch_operand_word(u16 byte);
u32 fetch_operand_dword(u16 byte);
u32 fetch_interrupt_handler(u8 number);

/* checkers */
b8 is_interrupt_reservered(u8 number);
b8 is_valid_opcode(u8 opcode);
b8 is_valid_register(u8 reg);
b8 is_valid_address(u32 addr);

void halt();
void clock_wait();
void instruction();
void interrupt(u8 number);

/* instructions */
void ins_mov();
void ins_add();
void ins_sub();
void ins_mul();
void ins_div();
void ins_jmp();
void ins_and();
void ins_or();
void ins_not();
void ins_xor();
void ins_shr();
void ins_shl();
void ins_push();
void ins_pop();
void ins_in();
void ins_out();
void ins_int();
void ins_set();
void ins_info();
void ins_nop();

int main() {
	memset(&cpu, 0, sizeof(cpu));
	cpu.memory.size = 0x00100000;
	cpu.memory.pointer = malloc(cpu.memory.size);
	if (cpu.memory.pointer == NULL) {
		printf("Failed to allocate memory sized %u\n", cpu.memory.size);
		return 1;
	}
	memset(cpu.memory.pointer, 0, cpu.memory.size);

	instructions[0x00] = ins_mov;
	instructions[0x01] = ins_add;
	instructions[0x02] = ins_sub;
	instructions[0x03] = ins_mul;
	instructions[0x04] = ins_div;
	instructions[0x05] = ins_jmp;
	instructions[0x06] = ins_and;
	instructions[0x07] = ins_or;
	instructions[0x08] = ins_not;
	instructions[0x09] = ins_xor;
	instructions[0x0A] = ins_shr;
	instructions[0x0B] = ins_shl;
	instructions[0x0C] = ins_push;
	instructions[0x0D] = ins_pop;
	instructions[0x0E] = ins_in;
	instructions[0x0F] = ins_out;
	instructions[0x10] = ins_int;
	instructions[0x11] = ins_set;
	instructions[0x12] = ins_info;
	instructions[0x13] = ins_nop;

	cpu.ip = 0x1000;

	cpu.memory.pointer[0x1000] = 0x03;
	cpu.memory.pointer[0x1001] = 0x02;
	cpu.memory.pointer[0x1002] = 0x01;
	cpu.memory.pointer[0x1003] = 0x01;
	cpu.memory.pointer[0x1004] = 0x01;

	cpu.memory.pointer[0x1005] = 0x06;
	cpu.memory.pointer[0x1006] = 0x11;
	cpu.memory.pointer[0x1007] = 0x01;
	cpu.memory.pointer[0x1008] = 0x00;
	cpu.memory.pointer[0x1009] = 0x10;
	cpu.memory.pointer[0x100A] = 0x00;
	cpu.memory.pointer[0x100B] = 0x00;

	while (!cpu.halt) {
		printf(
			"ra 0x%08X rb 0x%08X rc 0x%08X rd 0x%08X re 0x%08X rf 0x%08X rg 0x%08X rh 0x%08X\n"
			"sp 0x%08X bp 0x%08X ip 0x%08X\n",
			cpu.ra, cpu.rb, cpu.rc, cpu.rd, cpu.re, cpu.rf, cpu.rg, cpu.rh,
			cpu.sp, cpu.bp, cpu.ip
		);

		instruction();
	}
}

void clock_wait() {
	return;
}

u8 fetch_opcode() {
	if (cpu.ip >= cpu.memory.size) {
		return 0;
	}

	return cpu.memory.pointer[cpu.ip];
}

u8 fetch_modifier() {
	if (cpu.ip + 1 >= cpu.memory.size) {
		return 0;
	}

	return cpu.memory.pointer[cpu.ip + 1];
}

u8 fetch_operand_byte(u16 byte) {
	if (cpu.ip + 2 + byte >= cpu.memory.size) {
		return 0;
	}

	return cpu.memory.pointer[cpu.ip + 2 + byte];
}

u16 fetch_operand_word(u16 byte) {
	if (cpu.ip + 3 + byte >= cpu.memory.size) {
		return 0;
	}

	return cpu.memory.pointer[cpu.ip + 2 + byte] | cpu.memory.pointer[cpu.ip + 3 + byte] << 8;
}

u32 fetch_operand_dword(u16 byte) {
	if (cpu.ip + 5 + byte >= cpu.memory.size) {
		return 0;
	}

	return cpu.memory.pointer[cpu.ip + 2 + byte] | cpu.memory.pointer[cpu.ip + 3 + byte] << 8 | cpu.memory.pointer[cpu.ip + 4 + byte] << 16 | cpu.memory.pointer[cpu.ip + 5 + byte] << 24;
}

u32 fetch_interrupt_handler(u8 number) {
	if (cpu.int_lookup + 3 + number * 4 >= cpu.memory.size) {
		return 0;
	}

	return cpu.memory.pointer[cpu.int_lookup + number * 4] | cpu.memory.pointer[cpu.int_lookup + 1 + number * 4] << 8 | cpu.memory.pointer[cpu.int_lookup + 2 + number * 4] << 16 | cpu.memory.pointer[cpu.int_lookup + 3 + number * 4] << 24;
}

b8 is_interrupt_reservered(u8 number) {
	return (number <= 0x03 && number >= 0x00);
}

b8 is_valid_opcode(u8 opcode) {
	return (opcode <= 0x14 && opcode >= 0x01);
}

b8 is_valid_register(u8 reg) {
	return (reg <= 0x0B && reg >= 0x01);
}

b8 is_valid_address(u32 addr) {
	return (addr < cpu.memory.size);
}

void halt() {
	printf("Halt!\n");
	cpu.halt = 1;
}

void instruction() {
	u8 opcode = fetch_opcode();

	if (!is_valid_opcode(opcode)) {
		interrupt(0x02);
	} else {
		instructions[opcode - 1]();
	}
}

void interrupt(u8 number) {
	u32 handler = fetch_interrupt_handler(number);

	if (handler == 0 || handler >= cpu.memory.size) {
		if (is_interrupt_reservered(number)) {
			printf("Unhandled reserved interrupt 0x%02X\n", number);
			halt();
		}

		return;
	}

	cpu.ip = handler;
}

void ins_nop() {
	clock_wait();
}

void ins_mov() {
	u8 modifier = fetch_modifier();
	u8 ds = modifier & 0xF;
	u8 sz = modifier >> 0x4;

	if (sz == 0x0) {
		sz = 0x1;
	} else if (sz == 0x1) {
		sz = 0x2;
	} else if (sz == 0x2) {
		sz = 0x4;
	} else {
		interrupt(0x02);
		return;
	}

	if (ds == 0x0) {
		u8 dst = fetch_operand_byte(0);
		u8 src = fetch_operand_byte(1);

		if (!is_valid_register(dst) || !is_valid_register(src)) {
			interrupt(0x02);
			return;
		}

		cpu.regs[dst - 1] = cpu.regs[src - 1];
		cpu.ip += 4;
	} else if (ds == 0x1) {
		u8 dst = fetch_operand_byte(0);
		u32 src = 0;

		if (!is_valid_register(dst)) {
			interrupt(0x02);
			return;
		}

		if (sz == 0x1) {
			src = fetch_operand_byte(1);
		} else if (sz == 0x02) {
			src = fetch_operand_word(1);
		} else if (sz == 0x04) {
			src = fetch_operand_dword(1);
		}

		cpu.regs[dst - 1] = src;
		cpu.ip += 3 + sz;
	} else if (ds == 0x2) {
		u8 dst = fetch_operand_byte(0);
		u8 raddr = fetch_operand_byte(1);

		if (!is_valid_register(dst) || !is_valid_register(raddr)) {
			interrupt(0x02);
			return;
		}

		u32 addr = cpu.regs[raddr - 1];

		if (!is_valid_address(addr)) {
			halt();
			return;
		}

		cpu.regs[dst - 1] = cpu.memory.pointer[addr];
		cpu.ip += 4;
		clock_wait();
	} else if (ds == 0x3) {
		u8 rdst = fetch_operand_byte(0);
		u8 reg = fetch_operand_byte(1);

		if (!is_valid_register(reg) || !is_valid_register(rdst)) {
			interrupt(0x02);
			return;
		}

		u32 dst = cpu.regs[rdst - 1];

		if (!is_valid_address(dst)) {
			halt();
			return;
		}

		cpu.memory.pointer[dst] = cpu.regs[reg - 1];
		cpu.ip += 4;
		clock_wait();
	} else if (ds == 0x4) {
		u8 rdst = fetch_operand_byte(0);

		if (!is_valid_register(rdst)) {
			interrupt(0x02);
			return;
		}

		u32 dst = cpu.regs[rdst - 1];

		if (!is_valid_address(dst)) {
			halt();
			return;
		}

		if (sz == 0x01) {
			u8 src = fetch_operand_byte(1);
			cpu.memory.pointer[dst] = src;
		} else if (sz == 0x02) {
			u16 src = fetch_operand_word(1);
			cpu.memory.pointer[dst] = src;
			cpu.memory.pointer[dst + 1] = src >> 8;
		} else if (sz == 0x04) {
			u32 src = fetch_operand_dword(1);
			cpu.memory.pointer[dst] = src;
			cpu.memory.pointer[dst + 1] = src >> 8;
			cpu.memory.pointer[dst + 2] = src >> 16;
			cpu.memory.pointer[dst + 3] = src >> 24;
		} else {
			interrupt(0x02);
			return;
		}

		cpu.ip += 3 + sz;
		clock_wait();
	} else if (ds == 0x5) {
		u8 rdst = fetch_operand_byte(0);
		u8 raddr = fetch_operand_byte(1);

		if (!is_valid_register(rdst) || !is_valid_register(raddr)) {
			interrupt(0x02);
			return;
		}

		u32 dst = cpu.regs[rdst - 1];
		u32 addr = cpu.regs[raddr - 1];

		if (!is_valid_address(dst) || !is_valid_address(addr)) {
			halt();
			return;
		}
		
		if (sz == 0x01) {
			cpu.memory.pointer[dst] = cpu.memory.pointer[addr];
		} else if (sz == 0x01) {
			cpu.memory.pointer[dst] = cpu.memory.pointer[addr];
		} else if (sz == 0x02) {
			cpu.memory.pointer[dst] = cpu.memory.pointer[addr];
			cpu.memory.pointer[dst + 1] = cpu.memory.pointer[addr + 1];
		} else if (sz == 0x04) {
			cpu.memory.pointer[dst] = cpu.memory.pointer[addr];
			cpu.memory.pointer[dst + 1] = cpu.memory.pointer[addr + 1];
			cpu.memory.pointer[dst + 2] = cpu.memory.pointer[addr + 2];
			cpu.memory.pointer[dst + 3] = cpu.memory.pointer[addr + 3];
		} else {
			interrupt(0x02);
			return;
		}

		cpu.ip += 4;
		clock_wait();
		clock_wait();
		clock_wait();
	} else {
		interrupt(0x02);
		return;
	}

	clock_wait();
}

void ins_add() {
	u8 modifier = fetch_modifier();
	u8 tsd = modifier & 0xF;
	u8 sz = modifier >> 0x4;

	if (sz == 0x0) {
		sz = 0x1;
	} else if (sz == 0x1) {
		sz = 0x2;
	} else if (sz == 0x2) {
		sz = 0x4;
	} else {
		interrupt(0x02);
		return;
	}

	if (tsd == 0x0) {
		u8 dst = fetch_operand_byte(0);
		u8 src = fetch_operand_byte(1);
		u8 term = fetch_operand_byte(2);

		if (!is_valid_register(dst) || !is_valid_register(src) || !is_valid_register(term)) {
			interrupt(0x02);
			return;
		}

		if (sz == 0x01) {
			cpu.regs[dst - 1] = cpu.regs[src - 1] + cpu.regs[term - 1] & 0xFF;
		} else if (sz == 0x02) {
			cpu.regs[dst - 1] = cpu.regs[src - 1] + cpu.regs[term - 1] & 0xFFFF;
		} else if (sz == 0x04) {
			cpu.regs[dst - 1] = cpu.regs[src - 1] + cpu.regs[term - 1];
		} else {
			interrupt(0x02);
			return;
		}

		cpu.ip += 5;
	} else if (tsd == 0x1) {
		u8 dst = fetch_operand_byte(0);
		u8 src = fetch_operand_byte(1);
		u8 raddr = fetch_operand_byte(2);

		if (!is_valid_register(dst) || !is_valid_register(src) || !is_valid_register(raddr)) {
			interrupt(0x02);
			return;
		}

		u32 addr = cpu.regs[raddr - 1];

		if (!is_valid_address(addr)) {
			halt();
			return;
		}

		u32 term = 0;
		if (sz == 0x01) {
			term = cpu.memory.pointer[addr];
		} else if (sz == 0x02) {
			term = cpu.memory.pointer[addr] | cpu.memory.pointer[addr + 1] << 8;
		} else if (sz == 0x04) {
			term = cpu.memory.pointer[addr] | cpu.memory.pointer[addr + 1] << 8 | cpu.memory.pointer[addr + 2] << 16 | cpu.memory.pointer[addr + 3] << 24;
		} else {
			interrupt(0x02);
			return;
		}

		cpu.regs[dst - 1] = cpu.regs[src - 1] + term;
		cpu.ip += 5;
		clock_wait();
	} else if (tsd == 0x2) {
		u8 dst = fetch_operand_byte(0);
		u8 src = fetch_operand_byte(1);

		if (!is_valid_register(dst) || !is_valid_register(src)) {
			interrupt(0x02);
			return;
		}

		u32 term = 0;
		if (sz == 0x01) {
			term = fetch_operand_byte(2);
		} else if (sz == 0x02) {
			term = fetch_operand_word(2);
		} else if (sz == 0x04) {
			term = fetch_operand_dword(2);
		} else {
			interrupt(0x02);
			return;
		}

		cpu.regs[dst - 1] = cpu.regs[src - 1] + term;
		cpu.ip += 4 + sz;
	} else {
		interrupt(0x02);
		return;
	}

	clock_wait();
}

void ins_sub() {
	u8 modifier = fetch_modifier();
	u8 tsd = modifier & 0xF;
	u8 sz = modifier >> 0x4;

	if (sz == 0x0) {
		sz = 0x1;
	} else if (sz == 0x1) {
		sz = 0x2;
	} else if (sz == 0x2) {
		sz = 0x4;
	} else {
		interrupt(0x02);
		return;
	}

	if (tsd == 0x0) {
		u8 dst = fetch_operand_byte(0);
		u8 src = fetch_operand_byte(1);
		u8 term = fetch_operand_byte(2);

		if (!is_valid_register(dst) || !is_valid_register(src) || !is_valid_register(term)) {
			interrupt(0x02);
			return;
		}

		if (sz == 0x01) {
			cpu.regs[dst - 1] = cpu.regs[src - 1] - cpu.regs[term - 1] & 0xFF;
		} else if (sz == 0x02) {
			cpu.regs[dst - 1] = cpu.regs[src - 1] - cpu.regs[term - 1] & 0xFFFF;
		} else if (sz == 0x04) {
			cpu.regs[dst - 1] = cpu.regs[src - 1] - cpu.regs[term - 1];
		} else {
			interrupt(0x02);
			return;
		}

		cpu.ip += 5;
	} else if (tsd == 0x1) {
		u8 dst = fetch_operand_byte(0);
		u8 src = fetch_operand_byte(1);
		u8 raddr = fetch_operand_byte(2);

		if (!is_valid_register(dst) || !is_valid_register(src) || !is_valid_register(raddr)) {
			interrupt(0x02);
			return;
		}

		u32 addr = cpu.regs[raddr - 1];

		if (!is_valid_address(addr)) {
			halt();
			return;
		}

		u32 term = 0;
		if (sz == 0x01) {
			term = cpu.memory.pointer[addr];
		} else if (sz == 0x02) {
			term = cpu.memory.pointer[addr] | cpu.memory.pointer[addr + 1] << 8;
		} else if (sz == 0x04) {
			term = cpu.memory.pointer[addr] | cpu.memory.pointer[addr + 1] << 8 | cpu.memory.pointer[addr + 2] << 16 | cpu.memory.pointer[addr + 3] << 24;
		} else {
			interrupt(0x02);
			return;
		}

		cpu.regs[dst - 1] = cpu.regs[src - 1] - term;
		cpu.ip += 5;
		clock_wait();
	} else if (tsd == 0x2) {
		u8 dst = fetch_operand_byte(0);
		u8 src = fetch_operand_byte(1);

		if (!is_valid_register(dst) || !is_valid_register(src)) {
			interrupt(0x02);
			return;
		}

		u32 term = 0;
		if (sz == 0x01) {
			term = fetch_operand_byte(2);
		} else if (sz == 0x02) {
			term = fetch_operand_word(2);
		} else if (sz == 0x04) {
			term = fetch_operand_dword(2);
		} else {
			interrupt(0x02);
			return;
		}

		cpu.regs[dst - 1] = cpu.regs[src - 1] - term;
		cpu.ip += 4 + sz;
	} else {
		interrupt(0x02);
		return;
	}

	clock_wait();
}

void ins_mul() {
	u8 modifier = fetch_modifier();
	u8 tsd = modifier & 0xF;
	u8 sz = modifier >> 0x4;

	if (sz == 0x0) {
		sz = 0x1;
	} else if (sz == 0x1) {
		sz = 0x2;
	} else if (sz == 0x2) {
		sz = 0x4;
	} else {
		interrupt(0x02);
		return;
	}

	if (tsd == 0x0) {
		u8 dst = fetch_operand_byte(0);
		u8 src = fetch_operand_byte(1);
		u8 factor = fetch_operand_byte(2);

		if (!is_valid_register(dst) || !is_valid_register(src) || !is_valid_register(factor)) {
			interrupt(0x02);
			return;
		}

		if (sz == 0x01) {
			cpu.regs[dst - 1] = cpu.regs[src - 1] * cpu.regs[factor - 1] & 0xFF;
		} else if (sz == 0x02) {
			cpu.regs[dst - 1] = cpu.regs[src - 1] * cpu.regs[factor - 1] & 0xFFFF;
		} else if (sz == 0x04) {
			cpu.regs[dst - 1] = cpu.regs[src - 1] * cpu.regs[factor - 1];
		} else {
			interrupt(0x02);
			return;
		}

		cpu.ip += 5;
	} else if (tsd == 0x1) {
		u8 dst = fetch_operand_byte(0);
		u8 src = fetch_operand_byte(1);
		u8 raddr = fetch_operand_byte(2);

		if (!is_valid_register(dst) || !is_valid_register(src) || !is_valid_register(raddr)) {
			interrupt(0x02);
			return;
		}

		u32 addr = cpu.regs[raddr - 1];

		if (!is_valid_address(addr)) {
			halt();
			return;
		}

		u32 term = 0;
		if (sz == 0x01) {
			term = cpu.memory.pointer[addr];
		} else if (sz == 0x02) {
			term = cpu.memory.pointer[addr] | cpu.memory.pointer[addr + 1] << 8;
		} else if (sz == 0x04) {
			term = cpu.memory.pointer[addr] | cpu.memory.pointer[addr + 1] << 8 | cpu.memory.pointer[addr + 2] << 16 | cpu.memory.pointer[addr + 3] << 24;
		} else {
			interrupt(0x02);
			return;
		}

		cpu.regs[dst - 1] = cpu.regs[src - 1] * term;
		cpu.ip += 5;
		clock_wait();
	} else if (tsd == 0x2) {
		u8 dst = fetch_operand_byte(0);
		u8 src = fetch_operand_byte(1);

		if (!is_valid_register(dst) || !is_valid_register(src)) {
			interrupt(0x02);
			return;
		}

		u32 term = 0;
		if (sz == 0x01) {
			term = fetch_operand_byte(2);
		} else if (sz == 0x02) {
			term = fetch_operand_word(2);
		} else if (sz == 0x04) {
			term = fetch_operand_dword(2);
		} else {
			interrupt(0x02);
			return;
		}

		cpu.regs[dst - 1] = cpu.regs[src - 1] * term;
		cpu.ip += 4 + sz;
	} else {
		interrupt(0x02);
		return;
	}

	clock_wait();
}

void ins_div() {
	u8 modifier = fetch_modifier();
	u8 tsd = modifier & 0xF;
	u8 sz = modifier >> 0x4;

	if (sz == 0x0) {
		sz = 0x1;
	} else if (sz == 0x1) {
		sz = 0x2;
	} else if (sz == 0x2) {
		sz = 0x4;
	} else {
		interrupt(0x02);
		return;
	}

	if (tsd == 0x0) {
		u8 dst = fetch_operand_byte(0);
		u8 src = fetch_operand_byte(1);
		u8 factor = fetch_operand_byte(2);

		if (!is_valid_register(dst) || !is_valid_register(src) || !is_valid_register(factor)) {
			interrupt(0x02);
			return;
		}

		if (sz == 0x01) {
			cpu.regs[dst - 1] = cpu.regs[src - 1] / cpu.regs[factor - 1] & 0xFF;
		} else if (sz == 0x02) {
			cpu.regs[dst - 1] = cpu.regs[src - 1] / cpu.regs[factor - 1] & 0xFFFF;
		} else if (sz == 0x04) {
			cpu.regs[dst - 1] = cpu.regs[src - 1] / cpu.regs[factor - 1];
		} else {
			interrupt(0x02);
			return;
		}

		cpu.ip += 5;
	} else if (tsd == 0x1) {
		u8 dst = fetch_operand_byte(0);
		u8 src = fetch_operand_byte(1);
		u8 raddr = fetch_operand_byte(2);

		if (!is_valid_register(dst) || !is_valid_register(src) || !is_valid_register(raddr)) {
			interrupt(0x02);
			return;
		}

		u32 addr = cpu.regs[raddr - 1];

		if (!is_valid_address(addr)) {
			halt();
			return;
		}

		u32 term = 0;
		if (sz == 0x01) {
			term = cpu.memory.pointer[addr];
		} else if (sz == 0x02) {
			term = cpu.memory.pointer[addr] | cpu.memory.pointer[addr + 1] << 8;
		} else if (sz == 0x04) {
			term = cpu.memory.pointer[addr] | cpu.memory.pointer[addr + 1] << 8 | cpu.memory.pointer[addr + 2] << 16 | cpu.memory.pointer[addr + 3] << 24;
		} else {
			interrupt(0x02);
			return;
		}

		cpu.regs[dst - 1] = cpu.regs[src - 1] / term;
		cpu.ip += 5;
		clock_wait();
	} else if (tsd == 0x2) {
		u8 dst = fetch_operand_byte(0);
		u8 src = fetch_operand_byte(1);

		if (!is_valid_register(dst) || !is_valid_register(src)) {
			interrupt(0x02);
			return;
		}

		u32 term = 0;
		if (sz == 0x01) {
			term = fetch_operand_byte(2);
		} else if (sz == 0x02) {
			term = fetch_operand_word(2);
		} else if (sz == 0x04) {
			term = fetch_operand_dword(2);
		} else {
			interrupt(0x02);
			return;
		}

		cpu.regs[dst - 1] = cpu.regs[src - 1] / term;
		cpu.ip += 4 + sz;
	} else {
		interrupt(0x02);
		return;
	}

	clock_wait();
}

void ins_jmp() {
	u8 modifier = fetch_modifier();
	u8 addr_mod = modifier & 0xF;
	u8 variant = modifier >> 0x4;

	u32 addr = 0;
	u32 comparator = 0;
	u8 size = 0;

	if (addr_mod == 0x0) {
		u8 reg = fetch_operand_byte(0);
		u8 raddr = fetch_operand_byte(1);

		if (!is_valid_register(reg) || !is_valid_register(raddr)) {
			interrupt(0x02);
			return;
		}

		addr = cpu.regs[raddr - 1];

		if (!is_valid_address(addr)) {
			halt();
			return;
		}

		comparator = cpu.regs[reg - 1];
		size = 1;
	} else if (addr_mod == 0x1) {
		u8 reg = fetch_operand_byte(0);
		addr = fetch_operand_dword(1);

		if (!is_valid_register(reg)) {
			interrupt(0x02);
			return;
		}

		if (!is_valid_address(addr)) {
			halt();
			return;
		}

		comparator = cpu.regs[reg - 1];
		size = 4;
	} else {
		interrupt(0x02);
		return;
	}
	
	if (variant == 0x0) {
		cpu.ip = addr;
		goto skip_inc;
	} else if (variant == 0x1) {
		if (comparator != 0x00000000) {
			cpu.ip = addr;
			goto skip_inc;
		}
	} else if (variant == 0x2) {
		if (comparator == 0x00000000) {
			cpu.ip = addr;
			goto skip_inc;
		}
	} else if (variant == 0x3) {
		if (comparator & 0x800000000 == 0x00000000) {
			cpu.ip = addr;
			goto skip_inc;
		}
	} else if (variant == 0x4) {
		if (comparator & 0x800000000 != 0x00000000) {
			cpu.ip = addr;
			goto skip_inc;
		}
	} else if (variant == 0x5) {
		if (comparator & 0x800000000 == 0x00000000 || comparator == 0x00000000) {
			cpu.ip = addr;
			goto skip_inc;
		}
	} else if (variant == 0x6) {
		if (comparator & 0x800000000 != 0x00000000 || comparator == 0x00000000) {
			cpu.ip = addr;
			goto skip_inc;
		}
	} else {
		interrupt(0x02);
		return;
	}

	cpu.ip += 3 + size;

skip_inc:
	clock_wait();
}

void ins_and() {
	u8 modifier = fetch_modifier();
	u8 msd = modifier & 0xF;
	u8 sz = modifier >> 0x4;

	if (sz == 0x0) {
		sz = 0x1;
	} else if (sz == 0x1) {
		sz = 0x2;
	} else if (sz == 0x2) {
		sz = 0x4;
	} else {
		interrupt(0x02);
		return;
	}

	if (msd == 0x0) {
		u8 dst = fetch_operand_byte(0);
		u8 src = fetch_operand_byte(1);
		u8 mask = fetch_operand_byte(2);

		if (!is_valid_register(dst) || !is_valid_register(src) || !is_valid_register(mask)) {
			interrupt(0x02);
			return;
		}

		if (sz == 0x01) {
			cpu.regs[dst - 1] = cpu.regs[src - 1] & cpu.regs[mask - 1] & 0xFF;
		} else if (sz == 0x02) {
			cpu.regs[dst - 1] = cpu.regs[src - 1] & cpu.regs[mask - 1] & 0xFFFF;
		} else if (sz == 0x04) {
			cpu.regs[dst - 1] = cpu.regs[src - 1] & cpu.regs[mask - 1];
		} else {
			interrupt(0x02);
			return;
		}

		cpu.ip += 5;
	} else if (msd == 0x1) {
		u8 dst = fetch_operand_byte(0);
		u8 src = fetch_operand_byte(1);
		u8 raddr = fetch_operand_byte(2);

		if (!is_valid_register(dst) || !is_valid_register(src) || !is_valid_register(raddr)) {
			interrupt(0x02);
			return;
		}

		u32 addr = cpu.regs[raddr - 1];

		if (!is_valid_address(addr)) {
			halt();
			return;
		}

		u32 mask = 0;
		if (sz == 0x01) {
			mask = cpu.memory.pointer[addr];
		} else if (sz == 0x02) {
			mask = cpu.memory.pointer[addr] | cpu.memory.pointer[addr + 1] << 8;
		} else if (sz == 0x04) {
			mask = cpu.memory.pointer[addr] | cpu.memory.pointer[addr + 1] << 8 | cpu.memory.pointer[addr + 2] << 16 | cpu.memory.pointer[addr + 3] << 24;
		} else {
			interrupt(0x02);
			return;
		}

		cpu.regs[dst - 1] = cpu.regs[src - 1] & mask;
		cpu.ip += 5;
		clock_wait();
	} else if (msd == 0x2) {
		u8 dst = fetch_operand_byte(0);
		u8 src = fetch_operand_byte(1);

		if (!is_valid_register(dst) || !is_valid_register(src)) {
			interrupt(0x02);
			return;
		}

		u32 mask = 0;
		if (sz == 0x01) {
			mask = fetch_operand_byte(2);
		} else if (sz == 0x02) {
			mask = fetch_operand_word(2);
		} else if (sz == 0x04) {
			mask = fetch_operand_dword(2);
		} else {
			interrupt(0x02);
			return;
		}

		cpu.regs[dst - 1] = cpu.regs[src - 1] & mask;
		cpu.ip += 4 + sz;
	} else {
		interrupt(0x02);
		return;
	}

	clock_wait();
}

void ins_or() {
	u8 modifier = fetch_modifier();
	u8 msd = modifier & 0xF;
	u8 sz = modifier >> 0x4;

	if (sz == 0x0) {
		sz = 0x1;
	} else if (sz == 0x1) {
		sz = 0x2;
	} else if (sz == 0x2) {
		sz = 0x4;
	} else {
		interrupt(0x02);
		return;
	}

	if (msd == 0x0) {
		u8 dst = fetch_operand_byte(0);
		u8 src = fetch_operand_byte(1);
		u8 mask = fetch_operand_byte(2);

		if (!is_valid_register(dst) || !is_valid_register(src) || !is_valid_register(mask)) {
			interrupt(0x02);
			return;
		}

		if (sz == 0x01) {
			cpu.regs[dst - 1] = cpu.regs[src - 1] | cpu.regs[mask - 1] & 0xFF;
		} else if (sz == 0x02) {
			cpu.regs[dst - 1] = cpu.regs[src - 1] | cpu.regs[mask - 1] & 0xFFFF;
		} else if (sz == 0x04) {
			cpu.regs[dst - 1] = cpu.regs[src - 1] | cpu.regs[mask - 1];
		} else {
			interrupt(0x02);
			return;
		}

		cpu.ip += 5;
	} else if (msd == 0x1) {
		u8 dst = fetch_operand_byte(0);
		u8 src = fetch_operand_byte(1);
		u8 raddr = fetch_operand_byte(2);

		if (!is_valid_register(dst) || !is_valid_register(src) || !is_valid_register(raddr)) {
			interrupt(0x02);
			return;
		}

		u32 addr = cpu.regs[raddr - 1];

		if (!is_valid_address(addr)) {
			halt();
			return;
		}

		u32 mask = 0;
		if (sz == 0x01) {
			mask = cpu.memory.pointer[addr];
		} else if (sz == 0x02) {
			mask = cpu.memory.pointer[addr] | cpu.memory.pointer[addr + 1] << 8;
		} else if (sz == 0x04) {
			mask = cpu.memory.pointer[addr] | cpu.memory.pointer[addr + 1] << 8 | cpu.memory.pointer[addr + 2] << 16 | cpu.memory.pointer[addr + 3] << 24;
		} else {
			interrupt(0x02);
			return;
		}

		cpu.regs[dst - 1] = cpu.regs[src - 1] | mask;
		cpu.ip += 5;
		clock_wait();
	} else if (msd == 0x2) {
		u8 dst = fetch_operand_byte(0);
		u8 src = fetch_operand_byte(1);

		if (!is_valid_register(dst) || !is_valid_register(src)) {
			interrupt(0x02);
			return;
		}

		u32 mask = 0;
		if (sz == 0x01) {
			mask = fetch_operand_byte(2);
		} else if (sz == 0x02) {
			mask = fetch_operand_word(2);
		} else if (sz == 0x04) {
			mask = fetch_operand_dword(2);
		} else {
			interrupt(0x02);
			return;
		}

		cpu.regs[dst - 1] = cpu.regs[src - 1] | mask;
		cpu.ip += 4 + sz;
	} else {
		interrupt(0x02);
		return;
	}

	clock_wait();
}

void ins_not() {

}

void ins_xor() {
	u8 modifier = fetch_modifier();
	u8 msd = modifier & 0xF;
	u8 sz = modifier >> 0x4;

	if (sz == 0x0) {
		sz = 0x1;
	} else if (sz == 0x1) {
		sz = 0x2;
	} else if (sz == 0x2) {
		sz = 0x4;
	} else {
		interrupt(0x02);
		return;
	}

	if (msd == 0x0) {
		u8 dst = fetch_operand_byte(0);
		u8 src = fetch_operand_byte(1);
		u8 mask = fetch_operand_byte(2);

		if (!is_valid_register(dst) || !is_valid_register(src) || !is_valid_register(mask)) {
			interrupt(0x02);
			return;
		}

		if (sz == 0x01) {
			cpu.regs[dst - 1] = cpu.regs[src - 1] ^ cpu.regs[mask - 1] & 0xFF;
		} else if (sz == 0x02) {
			cpu.regs[dst - 1] = cpu.regs[src - 1] ^ cpu.regs[mask - 1] & 0xFFFF;
		} else if (sz == 0x04) {
			cpu.regs[dst - 1] = cpu.regs[src - 1] ^ cpu.regs[mask - 1];
		} else {
			interrupt(0x02);
			return;
		}

		cpu.ip += 5;
	} else if (msd == 0x1) {
		u8 dst = fetch_operand_byte(0);
		u8 src = fetch_operand_byte(1);
		u8 raddr = fetch_operand_byte(2);

		if (!is_valid_register(dst) || !is_valid_register(src) || !is_valid_register(raddr)) {
			interrupt(0x02);
			return;
		}

		u32 addr = cpu.regs[raddr - 1];

		if (!is_valid_address(addr)) {
			halt();
			return;
		}

		u32 mask = 0;
		if (sz == 0x01) {
			mask = cpu.memory.pointer[addr];
		} else if (sz == 0x02) {
			mask = cpu.memory.pointer[addr] | cpu.memory.pointer[addr + 1] << 8;
		} else if (sz == 0x04) {
			mask = cpu.memory.pointer[addr] | cpu.memory.pointer[addr + 1] << 8 | cpu.memory.pointer[addr + 2] << 16 | cpu.memory.pointer[addr + 3] << 24;
		} else {
			interrupt(0x02);
			return;
		}

		cpu.regs[dst - 1] = cpu.regs[src - 1] ^ mask;
		cpu.ip += 5;
		clock_wait();
	} else if (msd == 0x2) {
		u8 dst = fetch_operand_byte(0);
		u8 src = fetch_operand_byte(1);

		if (!is_valid_register(dst) || !is_valid_register(src)) {
			interrupt(0x02);
			return;
		}

		u32 mask = 0;
		if (sz == 0x01) {
			mask = fetch_operand_byte(2);
		} else if (sz == 0x02) {
			mask = fetch_operand_word(2);
		} else if (sz == 0x04) {
			mask = fetch_operand_dword(2);
		} else {
			interrupt(0x02);
			return;
		}

		cpu.regs[dst - 1] = cpu.regs[src - 1] ^ mask;
		cpu.ip += 4 + sz;
	} else {
		interrupt(0x02);
		return;
	}

	clock_wait();
}

void ins_shr() {
	u8 modifier = fetch_modifier();
	u8 ssd = modifier & 0xF;
	u8 sz = modifier >> 0x4;

	if (sz == 0x0) {
		sz = 0x1;
	} else if (sz == 0x1) {
		sz = 0x2;
	} else if (sz == 0x2) {
		sz = 0x4;
	} else {
		interrupt(0x02);
		return;
	}

	if (ssd == 0x0) {
		u8 dst = fetch_operand_byte(0);
		u8 src = fetch_operand_byte(1);
		u8 shifter = fetch_operand_byte(2);

		if (!is_valid_register(dst) || !is_valid_register(src) || !is_valid_register(shifter)) {
			interrupt(0x02);
			return;
		}

		if (sz == 0x01) {
			cpu.regs[dst - 1] = cpu.regs[src - 1] >> cpu.regs[shifter - 1] & 0xFF;
		} else if (sz == 0x02) {
			cpu.regs[dst - 1] = cpu.regs[src - 1] >> cpu.regs[shifter - 1] & 0xFFFF;
		} else if (sz == 0x04) {
			cpu.regs[dst - 1] = cpu.regs[src - 1] >> cpu.regs[shifter - 1];
		} else {
			interrupt(0x02);
			return;
		}

		cpu.ip += 5;
	} else if (ssd == 0x1) {
		u8 dst = fetch_operand_byte(0);
		u8 src = fetch_operand_byte(1);
		u8 raddr = fetch_operand_byte(2);

		if (!is_valid_register(dst) || !is_valid_register(src) || !is_valid_register(raddr)) {
			interrupt(0x02);
			return;
		}

		u32 addr = cpu.regs[raddr - 1];

		if (!is_valid_address(addr)) {
			halt();
			return;
		}

		u32 shifter = 0;
		if (sz == 0x01) {
			shifter = cpu.memory.pointer[addr];
		} else if (sz == 0x02) {
			shifter = cpu.memory.pointer[addr] | cpu.memory.pointer[addr + 1] << 8;
		} else if (sz == 0x04) {
			shifter = cpu.memory.pointer[addr] | cpu.memory.pointer[addr + 1] << 8 | cpu.memory.pointer[addr + 2] << 16 | cpu.memory.pointer[addr + 3] << 24;
		} else {
			interrupt(0x02);
			return;
		}

		cpu.regs[dst - 1] = cpu.regs[src - 1] >> shifter;
		cpu.ip += 5;
		clock_wait();
	} else if (ssd == 0x2) {
		u8 dst = fetch_operand_byte(0);
		u8 src = fetch_operand_byte(1);

		if (!is_valid_register(dst) || !is_valid_register(src)) {
			interrupt(0x02);
			return;
		}

		u32 shifter = 0;
		if (sz == 0x01) {
			shifter = fetch_operand_byte(2);
		} else if (sz == 0x02) {
			shifter = fetch_operand_word(2);
		} else if (sz == 0x04) {
			shifter = fetch_operand_dword(2);
		} else {
			interrupt(0x02);
			return;
		}

		cpu.regs[dst - 1] = cpu.regs[src - 1] >> shifter;
		cpu.ip += 4 + sz;
	} else {
		interrupt(0x02);
		return;
	}

	clock_wait();
}

void ins_shl() {
	u8 modifier = fetch_modifier();
	u8 ssd = modifier & 0xF;
	u8 sz = modifier >> 0x4;

	if (sz == 0x0) {
		sz = 0x1;
	} else if (sz == 0x1) {
		sz = 0x2;
	} else if (sz == 0x2) {
		sz = 0x4;
	} else {
		interrupt(0x02);
		return;
	}

	if (ssd == 0x0) {
		u8 dst = fetch_operand_byte(0);
		u8 src = fetch_operand_byte(1);
		u8 shifter = fetch_operand_byte(2);

		if (!is_valid_register(dst) || !is_valid_register(src) || !is_valid_register(shifter)) {
			interrupt(0x02);
			return;
		}

		if (sz == 0x01) {
			cpu.regs[dst - 1] = cpu.regs[src - 1] << cpu.regs[shifter - 1] & 0xFF;
		} else if (sz == 0x02) {
			cpu.regs[dst - 1] = cpu.regs[src - 1] << cpu.regs[shifter - 1] & 0xFFFF;
		} else if (sz == 0x04) {
			cpu.regs[dst - 1] = cpu.regs[src - 1] << cpu.regs[shifter - 1];
		} else {
			interrupt(0x02);
			return;
		}

		cpu.ip += 5;
	} else if (ssd == 0x1) {
		u8 dst = fetch_operand_byte(0);
		u8 src = fetch_operand_byte(1);
		u8 raddr = fetch_operand_byte(2);

		if (!is_valid_register(dst) || !is_valid_register(src) || !is_valid_register(raddr)) {
			interrupt(0x02);
			return;
		}

		u32 addr = cpu.regs[raddr - 1];

		if (!is_valid_address(addr)) {
			halt();
			return;
		}

		u32 shifter = 0;
		if (sz == 0x01) {
			shifter = cpu.memory.pointer[addr];
		} else if (sz == 0x02) {
			shifter = cpu.memory.pointer[addr] | cpu.memory.pointer[addr + 1] << 8;
		} else if (sz == 0x04) {
			shifter = cpu.memory.pointer[addr] | cpu.memory.pointer[addr + 1] << 8 | cpu.memory.pointer[addr + 2] << 16 | cpu.memory.pointer[addr + 3] << 24;
		} else {
			interrupt(0x02);
			return;
		}

		cpu.regs[dst - 1] = cpu.regs[src - 1] << shifter;
		cpu.ip += 5;
		clock_wait();
	} else if (ssd == 0x2) {
		u8 dst = fetch_operand_byte(0);
		u8 src = fetch_operand_byte(1);

		if (!is_valid_register(dst) || !is_valid_register(src)) {
			interrupt(0x02);
			return;
		}

		u32 shifter = 0;
		if (sz == 0x01) {
			shifter = fetch_operand_byte(2);
		} else if (sz == 0x02) {
			shifter = fetch_operand_word(2);
		} else if (sz == 0x04) {
			shifter = fetch_operand_dword(2);
		} else {
			interrupt(0x02);
			return;
		}

		cpu.regs[dst - 1] = cpu.regs[src - 1] << shifter;
		cpu.ip += 4 + sz;
	} else {
		interrupt(0x02);
		return;
	}

	clock_wait();
}

void ins_push() {
	u8 size = fetch_modifier();
	u8 reg = fetch_operand_byte(0);
}

void ins_pop() {

}

void ins_in() {

}

void ins_out() {

}

void ins_int() {

}

void ins_set() {

}

void ins_info() {

}