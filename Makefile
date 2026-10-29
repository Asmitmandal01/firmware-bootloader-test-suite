CC       = gcc
CFLAGS   = -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Werror -Iinclude
COVFLAGS = -std=c11 -O0 -g --coverage -Wall -Wextra -Iinclude

CORE_SRC = src/crc32.c src/flash_hal.c src/bootloader_fsm.c

.PHONY: all test verify clean

all: test verify

build:
	mkdir -p build results

test: build
	$(CC) $(COVFLAGS) $(CORE_SRC) tests/test_bootloader.c -o build/test_bootloader
	./build/test_bootloader
	$(CC) $(CFLAGS) $(CORE_SRC) src/device_server.c -o build/device_server

verify: test
	python3 scripts/run_verification_and_plots.py

clean:
	rm -rf build *.gcov
