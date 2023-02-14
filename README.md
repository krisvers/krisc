# krisc
A non-existent RISC CPU emulator with poor design decisions.

## ISA Details:

### instructions:

- little-endian significant bit position
- instructions have a fixed size at 3 bytes (24-bit)
- the first byte consists of two structures: macro opcode (the general instruction), and micro opcode which consists of one modifier bit, and three registers selector bits
- the next 2 bytes is a value, this can be used as an immediate or as an address depending on the modifier in the micro opcode

### macro opcodes and their binary representation:

- mov:      0b0000
- add:      0b0001
- sub:      0b0010
- cmp:      0b0011
- jmp:      0b0100
- mul:      0b0101
- div:      0b0110
- push/pop: 0b0111
- set/clr:  0b1000
- lod:      0b1001
- hlt/rbt:	0b1010
- out:		0b1011
- in:		0b1100

### modifier bit:

- non-memory:  0b0
- memory:	   0b1

### registers:

- a:		 0b000
- b:		 0b001
- c:		 0b010
- d:		 0b011
- e:		 0b100
- f:		 0b101
- sp:		 0b110
- bp:		 0b111

### examples:

- mov a, 0x5:		0000 0 000 00000101 00000000
- mov [0x100], b:	0000 1 001 00000000 00000001
- add f, 0x33F9:	0001 0 101 11111001 00110011
- jmp [0x20F]:		0100 0 000 00001111 00000010
- cmp d, 0x7F:		0011 0 011 01111111 00000000
- lod e, [0x69]:	1001 0 100 01101001 00000000
- stc:				1000 1 001 00000000 00000000
- clo:				1000 0 010 00000000 00000000
- hlt:				1010 1 000 00000000 00000000
- rbt:				1010 0 000 00000000 00000000
- out 0x10, a:		1011 0 000 00001010 00000000
- out 0x18, 0x9:	1011 1 000 00010010 00001000
- in d, 0x6F:		1100 0 011 01101111 00000000
- push f:			0111 1 101 00000000 00000000
- pop b:			0111 0 001 00000000 00000000

### tiny things:

- mov doesn't read from memory, only write to; lod reads from memory and places the value in the specified register
- rbt is insanely fast so watch out
- io may be finicky

### how to setup stack:

- 1st: set the base pointer:	mov bp, 0x100 -> 0000 0 111 00000000 00000001
- 2nd: set the stack pointer:	mov sp, 0x100 -> 0000 0 110 00000000 00000001
- 3rd: push and pop all you want, just make sure not to overflow or underflow! :)

### jumps:

#### example:

- jmp:		0100 0 000 [address]
- je/jz:	0100 0 001 [address]
- jg:		0100 0 010 [address]
- jl:		0100 0 011 [address]
- jge:		0100 0 100 [address]
- jle:		0100 0 101 [address]
- jc:		0100 0 110 [address]
- jo:		0100 0 111 [address]
- jne/jnz:	0100 1 000 [address]
- jnc:		0100 1 001 [address]
- jno:		0100 1 010 [address]
