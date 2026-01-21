
CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99
LINK = -lpcap

all: clean trace

trace: trace.o checksum.o
	$(CC) $(CFLAGS) -o trace trace.o checksum.o $(LINK)

trace.o: checksum.c checksum.h
	$(CC) $(CFLAGS) -c trace.c

checksum.o: checksum.c
	$(CC) $(CFLAGS) -c checksum.c

clean:
	rm -f *.o trace
