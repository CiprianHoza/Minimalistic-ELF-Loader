# Minimalistic ELF Loader

A lightweight, educational ELF loader for Linux capable of loading and executing several types of statically linked binaries. This project demonstrates low-level binary loading techniques, manual memory mapping, and transferring control to user programs without relying on the system dynamic loader.

## Features

- **Supports multiple binary types**
  - Minimal static binaries using direct Linux syscalls  
  - Statically linked **non-PIE** C programs using `libc`  
  - Statically linked **PIE** executables

- **Manual ELF parsing and loading**
  - Reads and validates ELF headers and program headers  
  - Maps loadable segments with correct memory permissions  
  - Applies necessary relocations for static PIEs

- **Custom runtime setup**
  - Constructs the initial stack (`argv`, `envp`, auxiliary vectors)  
  - Transfers control to the binary’s entry point

- **Small and self-contained**
  - No reliance on the system dynamic loader  
  - Compact codebase focused on clarity and low-level control

## Building

```sh
make
```

## Usage

```sh
./elf-loader <path-to-static-binary>
```
