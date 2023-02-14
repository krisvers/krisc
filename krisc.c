#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define CODE_LENGTH 512

#define DEFAULT_MEM_SIZE 8192

uint8_t code[CODE_LENGTH] = { 0b00000110, 0x00, 0x01, 0b00000111, 0x00, 0x01, 0, 0x69, 0x00, 0b10001000, 0, 0, 0b10000001, 0, 0 };
uint8_t stepping = 0;

struct Registers {
    uint8_t a, b, c, d;
    uint16_t e, f;
    uint16_t sp, bp, pc;
} registers;

void * registers_array[9] = { &registers.a, &registers.b, &registers.c, &registers.d, &registers.e, &registers.f, &registers.sp, &registers.bp, &registers.pc };

struct Flags {
    uint8_t error, carry, overflow, greater, lesser : 1;
} flags;

struct Memory {
    uint16_t size;
    uint8_t * memory_array;
} memory;

void print_stack() {
	for (int i = 0; registers.bp - i > registers.sp; i++) {
		printf(" %x", memory.memory_array[registers.bp - i]);
	}
}

void print_status() {
    system("clear");
    printf("a: %x\tb: %x\tc: %x\td: %x\te: %x\tf: %x\nsp: %x\tbp: %x\tpc: %x\nopcode: %x\tvalue: %x\nerror: %x\tcarry: %x\toverflow: %x\tgreater: %x\tlesser: %x\nmem size: %x bytes\nstepping %x\nstack:",
    registers.a, registers.b, registers.c, registers.d, registers.e, registers.f, registers.sp, registers.bp, registers.pc, memory.memory_array[registers.pc], memory.memory_array[registers.pc + 1] | memory.memory_array[registers.pc + 2] << 8, flags.error, flags.carry, flags.overflow, flags.greater, flags.lesser, memory.size, stepping);
    print_stack();
    putc('\n', stdout);
}

/*
instructions: mov, add, sub, cmp, jmp, ...
every instruction contains a macro opcode (4 bits), a micro opcode (4 bits), and a value (16 bits)

for example, `mov a, 0x20` translates to `0000 0000 00100000 00000000`
mov is a macro opcode `0000`
a is the micro opcode, and destination `0000`
0x20 is a value `00100000 00000000

another example, `cmp f, 0x30FF` translates to `0011 0101 11111111 00110000`
cmp is the macro opcode `0011`
f is the first argument `0101`
0x30FF is the second argument `11111111 00110000`
*/

int run_instruction(uint16_t ptr) {
    uint8_t opcode = memory.memory_array[ptr];
    uint16_t value = memory.memory_array[ptr + 1] | memory.memory_array[ptr + 2] << 8;

    switch (opcode >> 4) {
        // mov [reg], [immediate]
        // or
        // mov [address], [reg]
        case 0:
            if (opcode & 0b1000) {
                if (value >= memory.size) {
                    return 2;
                }

                if ((opcode & 0b0111) >= 4) {
                    memory.memory_array[value] = *((uint16_t *) registers_array[opcode & 0b0111]);
                    break;
                }

                memory.memory_array[value] = *((uint8_t *) registers_array[opcode & 0b0111]);
                break;
            }

            if ((opcode & 0b0111) >= 4) {
                *((uint16_t *) registers_array[opcode & 0b0111]) = value;
                break;
            }

            *((uint8_t *) registers_array[opcode & 0b0111]) = value;
            break;

        case 1:
            if (opcode & 0b1000) {
                if (value >= memory.size) {
                    return 2;
                }

                if ((opcode & 0b0111) >= 4) {
                    memory.memory_array[value] += *((uint16_t *) registers_array[opcode & 0b0111]);
                    break;
                }

                memory.memory_array[value] += *((uint8_t *) registers_array[opcode & 0b0111]);
                break;
            }

            if ((opcode & 0b0111) >= 4) {
                *((uint16_t *) registers_array[opcode & 0b0111]) += value;
                break;
            }

            *((uint8_t *) registers_array[opcode & 0b0111]) += value;
            break;

        case 2:
            if (opcode & 0b1000) {
                if (value >= memory.size) {
                    return 2;
                }

                if ((opcode & 0b0111) >= 4) {
                    memory.memory_array[value] -= *((uint16_t *) registers_array[opcode & 0b0111]);
                    break;
                }

                memory.memory_array[value] -= *((uint8_t *) registers_array[opcode & 0b0111]);
                break;
            }

            if ((opcode & 0b0111) >= 4) {
                *((uint16_t *) registers_array[opcode & 0b0111]) -= value;
                break;
            }

            *((uint8_t *) registers_array[opcode & 0b0111]) -= value;
            break;

        case 3:
            if (opcode & 0b1000) {
                if (value >= memory.size) {
                    return 2;
                }

                if ((opcode & 0b0111) < 4) {
                    flags.lesser = 0;
                    flags.greater = 0;
                    if (*((uint8_t *) registers_array[opcode & 0b0111]) == memory.memory_array[value]) {
                        flags.lesser = 1;
                        flags.greater = 1;
                    }
                    if (*((uint8_t *) registers_array[opcode & 0b0111]) > memory.memory_array[value]) {
                        flags.greater = 1;
                    }
                    if (*((uint8_t *) registers_array[opcode & 0b0111]) < memory.memory_array[value]) {
                        flags.lesser = 1;
                    }

                    break;
                }

                flags.lesser = 0;
                flags.greater = 0;
                if (*((uint16_t *) registers_array[opcode & 0b0111]) == memory.memory_array[value]) {
                    flags.lesser = 1;
                    flags.greater = 1;
                }
                if (*((uint16_t *) registers_array[opcode & 0b0111]) > memory.memory_array[value]) {
                    flags.greater = 1;
                }
                if (*((uint16_t *) registers_array[opcode & 0b0111]) < memory.memory_array[value]) {
                    flags.lesser = 1;
                }

                break;
            }

            if ((opcode & 0b0111) >= 4) {
                flags.lesser = 0;
                flags.greater = 0;
                if (*((uint16_t *) registers_array[opcode & 0b0111]) == value) {
                    flags.lesser = 1;
                    flags.greater = 1;
                }
                if (*((uint16_t *) registers_array[opcode & 0b0111]) > value) {
                    flags.greater = 1;
                }
                if (*((uint16_t *) registers_array[opcode & 0b0111]) < value) {
                    flags.lesser = 1;
                }

                break;
            }
            
            flags.lesser = 0;
            flags.greater = 0;
            if (*((uint8_t *) registers_array[opcode & 0b0111]) == value) {
                flags.lesser = 1;
                flags.greater = 1;
            }
            if (*((uint8_t *) registers_array[opcode & 0b0111]) > value) {
                flags.greater = 1;
            }
            if (*((uint8_t *) registers_array[opcode & 0b0111]) < value) {
                flags.lesser = 1;
            }
            break;

        case 4:
            if (value >= memory.size) {
                return 2;
            }

            switch (opcode & 0b1111) {
                case 0: // unconditional
                    registers.pc = value;
                    return 1;
                
                case 1: // equal / zero
                    if (flags.lesser && flags.greater) {
                        registers.pc = value;
                        return 1;
                    }

                    break;

                case 2: // greater
                    if (flags.greater && !flags.lesser) {
                        registers.pc = value;
                        return 1;
                    }

                    break;
                
                case 3: // lesser
                    if (flags.lesser && !flags.greater) {
                        registers.pc = value;
                        return 1;
                    }

                    break;
                
                case 4: // greater or equal
                    if (flags.greater) {
                        registers.pc = value;
                        return 1;
                    }

                    break;
                
                case 5: // less or equal
                    if (flags.lesser) {
                        registers.pc = value;
                        return 1;
                    }

                    break;
                
                case 6: // carry
                    if (flags.carry) {
                        registers.pc = value;
                        return 1;
                    }

                    break;
                
                case 7: // overflow
                    if (flags.overflow) {
                        registers.pc = value;
                        return 1;
                    }

                    break;
                
                case 8: // not equal / not zero
                    if (!(flags.greater && flags.lesser)) {
                        registers.pc = value;
                        return 1;
                    }

                    break;
                
                case 9: // not carry
                    if (!flags.carry) {
                        registers.pc = value;
                        return 1;
                    }

                    break;
                
                case 10: // not overflow
                    if (!flags.overflow) {
                        registers.pc = value;
                        return 1;
                    }

                    break;

                default:
                    break;
                    
            }

            break;

        case 5:
            if (opcode & 0b1000) {
                if ((opcode & 0b0111) >= 4) {
                    uint32_t product = *((uint16_t *) registers_array[opcode & 0b0111]) * memory.memory_array[value];
                    if (product > UINT16_MAX) {
                        flags.overflow = 1;
                    }

                    registers.e = product;
                    break;
                }
                
                uint16_t product = *((uint8_t *) registers_array[opcode & 0b0111]) * memory.memory_array[value];
                if (product > UINT8_MAX) {
                    flags.overflow = 1;
                }

                registers.e = product;
                break;
            }

            if ((opcode & 0b0111) >= 4) {
                uint32_t product = *((uint16_t *) registers_array[opcode & 0b0111]) * value;
                if (product > UINT16_MAX) {
                    flags.overflow = 1;
                }

                registers.e = product;
                break;
            }
            
            uint16_t product = *((uint8_t *) registers_array[opcode & 0b0111]) * value;
            if (product > UINT8_MAX) {
                flags.overflow = 1;
            }

            registers.e = product;
            break;

        case 6:
            if (opcode & 0b1000) {
                if ((opcode & 0b0111) >= 4) {
                    registers.f = *((uint16_t *) registers_array[opcode & 0b0111]) / memory.memory_array[value];
                    break;
                }

                registers.f = *((uint8_t *) registers_array[opcode & 0b0111]) / memory.memory_array[value];
                break;
            }

            if ((opcode & 0b0111) >= 4) {
                registers.f = *((uint16_t *) registers_array[opcode & 0b0111]) / value;
                break;
            }

            registers.f = *((uint8_t *) registers_array[opcode & 0b0111]) / value;
            break;

        case 7: // setting & clearing flags
            // setting
            if (opcode & 0b1000) {
                switch (opcode & 0b0111) {
                    case 0:
                        flags.error = 1;
                        return 0;
                    case 1:
                        flags.carry = 1;
                        return 0;
                    case 2:
                        flags.overflow = 1;
                        return 0;
                    case 3:
                        flags.greater = 1;
                        return 0;
                    case 4:
                        flags.lesser = 1;
                        return 0;
                    default:
                        return 3;
                }
            }

            switch (opcode & 0b0111) {
                case 0:
                    flags.error = 0;
                    return 0;
                case 1:
                    flags.carry = 0;
                    return 0;
                case 2:
                    flags.overflow = 0;
                    return 0;
                case 3:
                    flags.greater = 0;
                    return 0;
                case 4:
                    flags.lesser = 0;
                    return 0;
                default:
                    return 3;
            }

        case 8:
            if (opcode & 0b1000) {
                if (registers.sp < 1) {
                    return 5;
                }

                if ((opcode & 0b0111) >= 4) {
                    if (registers.sp < 2) {
                        return 5;
                    }

                    memory.memory_array[registers.sp] = *((uint16_t *) registers_array[opcode & 0b0111]) >> 8;
                    registers.sp--;
                    memory.memory_array[registers.sp] = *((uint16_t *) registers_array[opcode & 0b0111]) & 0b11111111;
                    registers.sp--;
                    break;
                }

                memory.memory_array[registers.sp] = *((uint8_t *) registers_array[opcode & 0b0111]);
                registers.sp--;
                break;
            }

            if ((opcode & 0b0111) >= 4) {
                if (registers.sp >= registers.bp) {
                    return 5;
                }

                if (registers.sp == registers.bp - 1) {
                    *((uint16_t *) registers_array[opcode & 0b0111]) = memory.memory_array[registers.sp++];
                    break;
                }

                *((uint16_t *) registers_array[opcode & 0b0111]) = memory.memory_array[registers.sp++] << 8 | memory.memory_array[registers.sp++];
                break;
            }

            *((uint8_t *) registers_array[opcode & 0b0111]) = memory.memory_array[registers.sp++];
            break;

        case 9:
            if (opcode & 0b1000) {
                break;
            }

            *((uint8_t *) registers_array[opcode & 0b0111]) = memory.memory_array[value];
            break;

        default:
            return 3;
    }

    return 0;
}

int boot() {
    int instruction_return;
    char input;
    stepping = 1;
    while (1) {
        print_status();

        input = 0;
        while (input != '\n') { input = getc(stdin); if (input == 'y') { stepping = 1; break; } else if (input == 'n') { stepping = 0; break; } if (!stepping) { break; } }

		if (registers.pc >= memory.size) {
			return 2;
		}

        instruction_return = run_instruction(registers.pc);
        switch (instruction_return) {
            case 0:
                registers.pc += 3;
                break;
            case 1: // do not increment pc
                break;
            case 2: // invalid memory address
                return 2;
            case 3: // invalid opcode
                return 3;
            case 4: // divide by zero
                return 4;
            case 5:
                return 5;
            default:
                return 99;
        }
    }

    return 0;
}

int main(int argc, char ** argv) {
    if (argc > 2) {
        printf("Provide a binary file or no file.\n");
        return -1;
    }

    memory.size = DEFAULT_MEM_SIZE;
    memory.memory_array = malloc(memory.size);

    if (argc != 2) {
        for (int i = 0; i < CODE_LENGTH; i++) {
            memory.memory_array[i] = code[i];
        }
    }

    if (argc == 2) {
        FILE * fp = fopen(argv[1], "r");
        if (fp == NULL) {
            printf("Could not read from file!\n");
            return -2;
        }

        int c = 0;

        for (int i = 0; c != EOF && i < memory.size; i++) {
            c = fgetc(fp);
            memory.memory_array[i] = c;
        }
        
        fclose(fp);
    }

    int return_code = boot();

    switch (return_code) {
        case 0:
            printf("CPU powered off successfully!\n");
            return 0;
        case 1:
            printf("CPU ran into an error!\n");
            return 1;
        case 2:
            printf("CPU tried to access an invalid memory address!\n");
            return 2;
        case 3:
            printf("Invalid opcode!\n");
            return 3;
        case 4:
            printf("Divide by zero!\n");
            return 4;
        case 5:
            printf("Stack overflow!\n");
            return 5;
        default:
            printf("Unknown return code!\n");
            return -1;
    }
}
