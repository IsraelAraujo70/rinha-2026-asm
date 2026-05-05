# Pure-asm build: nasm + ld, freestanding ELF static binaries.
# No libc, no compiler driver.

NASM      ?= nasm
LD        ?= ld
NASMFLAGS := -f elf64 -g -F dwarf
LDFLAGS   := -nostdlib -static

BUILD     := build
RUNTIME_SRC := $(wildcard runtime/*.asm)
RUNTIME_OBJ := $(patsubst runtime/%.asm,$(BUILD)/runtime/%.o,$(RUNTIME_SRC))

.PHONY: all api clean

all: api

api: $(BUILD)/api

$(BUILD)/api: $(RUNTIME_OBJ)
	@mkdir -p $(@D)
	$(LD) $(LDFLAGS) -o $@ $^

$(BUILD)/runtime/%.o: runtime/%.asm $(wildcard runtime/*.inc)
	@mkdir -p $(@D)
	$(NASM) $(NASMFLAGS) -I runtime/ -o $@ $<

clean:
	rm -rf $(BUILD)
