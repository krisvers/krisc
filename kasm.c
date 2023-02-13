#include <stdio.h>
#include <string.h>
#include <stdint.h>

uint8_t binary_buffer[32];
uint8_t buffer_i = 0;
uint8_t nibble = 0;
uint8_t not = 0;

int main(int argc, char ** argv) {
	if (argc > 3 || argc < 2) {
		printf("kasm [file] [out file]!\n");
		return 1;
	}

	FILE * outfp;
	FILE * infp;
	int c = 0;

	if (argc == 3) {
		outfp = fopen(argv[2], "w");
	} else {
		outfp = fopen("kout.bin", "w");
	}

	infp = fopen(argv[1], "r");
	if (infp == NULL) {
		printf("No such file!\n");
		return 2;
	}

	while ((c = fgetc) != EOF) {
		switch (c) {
			case 'm':
				binary_buffer[buffer_i] = 0b00000000;
				nibble = 1;
				break;
			case 'a':
				binary_buffer[buffer_i] = 0b00010000;
				nibble = 1;
				break;
			case 's':
				binary_buffer[buffer_i] = 0b00100000;
				nibble = 1;
				break;
			case 'c':
				binary_buffer[buffer_i] = 0b00110000;
				nibble = 1;
				break;
			case 'j':
				binary_buffer[buffer_i] = 0b01000000;
				nibble = 1;
				break;
			case 'x':
				binary_buffer[buffer_i] = 0b01010000;
				nibble = 1;
				break;
			case 'd':
				binary_buffer[buffer_i] = 0b01100000;
				nibble = 1;
				break;
			case 'p':
				binary_buffer[buffer_i] = 0b01111000;
				nibble = 1;
				break;
			case 'o':
				if (nibble) {
					if (not) {
						binary_buffer[buffer_i] |= 0b1010;
					} else {
						binary_buffer[buffer_i] |= 0b0111;
					}
					
					nibble = 0;
					buffer_i++;
					break;
				}

				binary_buffer[buffer_i] = 0b01110000;
				nibble = 1;
				break;
			case 't':
				binary_buffer[buffer_i] = 0b10001000;
				nibble = 1;
				break;
			case 'l':
				if (nibble) {
					binary_buffer[buffer_i] |= 0b0011;
					nibble = 0;
					buffer_i++;
					break;
				}

				binary_buffer[buffer_i] = 0b10000000;
				nibble = 1;
				break;
			case 'g':
				if (nibble) {
					binary_buffer[buffer_i] |= 0b0010;
					nibble = 0;
					buffer_i++;
					break;
				}
			case 'n':
				not = 1;
				break;
		}
	}
}