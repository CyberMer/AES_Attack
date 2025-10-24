# Simple Makefile for AES square attack
CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99
SRCDIR = cry_eng2021_tp_aessq

all: aes_key_recovery

aes_key_recovery: aes_key_recovery.c aes-128_attack.h $(SRCDIR)/aes-128_enc.c $(SRCDIR)/aes-128_enc.h
	$(CC) $(CFLAGS) -I$(SRCDIR) -o $@ aes_key_recovery.c $(SRCDIR)/aes-128_enc.c

test: aes_key_recovery
	./aes_key_recovery

clean:
	rm -f aes_key_recovery

.PHONY: all test clean