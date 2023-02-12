# krisc
A non-existent RISC CPU emulator with poor design decisions.

## ISA Details:

### instructions:

- instructions have a fixed size at 3 bytes (24-bit)
- the first byte consists of two structures: macro opcode (the general instruction), and micro opcode (a modifier and register selector)
- each are 4 bits long
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

#### mov:

mov has 2 different types (register destination and memory destination)

by default it uses register destination
