all: krisc

krisc:
	gcc krisc.c -o kriscemu -Wall

asm:
	gcc kasm.c -o kasm -Wall
