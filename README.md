# slac33

Epson S1C33000 support in Ghidra.

Work in progress. Currently able to disassemble raw binaries fine. Decompilation/P-code implementation needs polishing. Analysis of ELF objects does not work yet due to lack of an architecture-specific parser for relocations, etc.

Not a fork of [s1c33_sleigh](https://github.com/GMMan/s1c33_sleigh). 

## Install

Use gradle to build the extension.

If `GHIDRA_INSTALL_DIR` is correctly defined, run

```sh
gradle
```

Or, in case it is not defined or you wish to build it for a Ghidra version different than what is specified in `GHIDRA_INSTALL_DIR`, use

```sh
gradle -PGHIDRA_INSTALL_DIR=<Absolute path to Ghidra>
```

## Disassembly syntax

The disassembly syntax is a simplified version inspired by the Capstone syntax and Arm assembly syntax, and is slightly different from Epson's. Specifically:

- Extended instructions do not have the `x` prefix.
- Registers do not have the `%` prefix.
- `.w` suffix are omitted.
- `ld.*` that loads to RAM is renamed to `st` (short for store) and with its operands reversed. `ld.*` that loads from immediate is renamed to `mov`.
- `pushn` and `popn` have the syntax of `pushn {:rs}` and `popn {:rd}` to illustrate how the pushed elements look like on the stack from lower to higher address.

If an instruction is delayed, an underscore (`_`) gets added to the beginning of mnemonic (`add` -> `_add`). This is done by Ghidra.
