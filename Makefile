CC=gcc
CFLAG=-g

all: mokutil

efilib: efilib.c
	$(CC) $(CFLAG) -c efilib.c

mokutil: efilib mokutil.c
	$(CC) $(CFLAG) efilib.o mokutil.c -o mokutil

clean:
	rm -f mokutil *.o
