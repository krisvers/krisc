all: krisc

krisc:
	gcc krisc.c -o kriscemu -Wall

kasm:
	gcc kasm.c -o kasm -Wall