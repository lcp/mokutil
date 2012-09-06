CC = gcc
CFLAGS = -g

all: mokutil

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

mokutil: efilib.o mokutil.o
	$(CC) $(CFLAGS) efilib.o mokutil.o -o $@

clean:
	rm -f mokutil *.o
