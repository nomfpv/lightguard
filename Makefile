CC ?= cc
CFLAGS ?= -Os -Wall -Wextra

lightguard: src/lin.c src/lgcore.c src/lgcore.h
	$(CC) $(CFLAGS) -o $@ src/lin.c src/lgcore.c
	-strip $@

clean:
	rm -f lightguard

.PHONY: clean
