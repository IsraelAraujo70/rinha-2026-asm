# Pure-asm build: nasm + ld, freestanding ELF static binaries.
# No libc, no compiler driver.

NASM       ?= nasm
LD         ?= ld
NASMFLAGS  := -f elf64 -g -F dwarf
BENCHFLAGS := $(NASMFLAGS) -DBENCH_BUILD
LDFLAGS    := -nostdlib -static

BUILD := build

.PHONY: all api bench clean

all: api

# ---- API binary ----
api: $(BUILD)/api

$(BUILD)/api: $(BUILD)/runtime/api.o
	@mkdir -p $(@D)
	$(LD) $(LDFLAGS) -o $@ $^

$(BUILD)/runtime/%.o: runtime/%.asm $(wildcard runtime/*.inc)
	@mkdir -p $(@D)
	$(NASM) $(NASMFLAGS) -I runtime/ -o $@ $<

# ---- Bench harness (offline, reuses api.asm sans _start) ----
bench: $(BUILD)/bench

$(BUILD)/bench: $(BUILD)/bench-objs/api.o $(BUILD)/bench-objs/bench.o
	@mkdir -p $(@D)
	$(LD) $(LDFLAGS) -o $@ $^

$(BUILD)/bench-objs/%.o: runtime/%.asm $(wildcard runtime/*.inc)
	@mkdir -p $(@D)
	$(NASM) $(BENCHFLAGS) -I runtime/ -o $@ $<

clean:
	rm -rf $(BUILD)
