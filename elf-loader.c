#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>

// ELF file offsets
#define E_PHOFF 0x20
#define E_PHENTSIZE 0x36
#define E_PHNUM 0x38
#define E_ENTRY 0x18
#define E_TYPE 0x10
#define ET_DYN 3

// ELF file segments offsets
#define P_FLAGS 0x04
#define P_VADDR 0x10
#define P_OFFSET 0x08
#define P_FILESZ 0x20
#define P_MEMSZ 0x28

// Auxv values
#define AT_RANDOM 25
#define AT_ENTRY 9
#define AT_PAGESZ 6
#define AT_PHNUM 5
#define AT_PHENT 4
#define AT_PHDR 3
#define AT_EXECFN 31
#define AT_BASE 7

void *map_elf(const char *filename)
{
	// This part helps you store the content of the ELF file inside the buffer.
	struct stat st;
	void *file;
	int fd;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		perror("OPEN FAILED");
		exit(1);
	}

	fstat(fd, &st);

	file = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (file == MAP_FAILED) {
		perror("MAP_FAILED");
		close(fd);
		exit(1);
	}

	return file;
}

int get_prot(unsigned long flags)
{
	int prot = 0;

	if (flags & 0x4)
		prot |= PROT_READ;
	if (flags & 0x2)
		prot |= PROT_WRITE;
	if (flags & 0x1)
		prot |= PROT_EXEC;

	return prot;
}

void load_and_run(const char *filename, int argc, char **argv, char **envp)
{
	// Contents of the ELF file are in the buffer: elf_contents[x] is the x-th byte of the ELF file.
	void *elf_contents = map_elf(filename);
	int i;

	// ELF file identification
	unsigned char aux[5];

	for (i = 0; i < 4; i++)
		aux[i] = ((unsigned char *)elf_contents)[i];
	aux[4] = '\0';
	if (aux[0] != 0x7f || strcmp(aux + 1, "ELF") != 0) {
		fprintf(stderr, "Not a valid ELF file");
		exit(3);
	}
	if (*((char *)elf_contents + 4) != 2) {
		fprintf(stderr, "Not a 64-bit ELF");
		exit(4);
	}

	// Loading in memory of every PT_LOAD segment with the right permissions
	short int nr = *(short int *)((unsigned char *)elf_contents + E_PHNUM);
	short int size = *(short int *)((unsigned char *)elf_contents + E_PHENTSIZE);
	unsigned short e_type = *(unsigned short *)((unsigned char *)elf_contents + E_TYPE);
	unsigned long phoff = *(unsigned long *)((unsigned char *)elf_contents + E_PHOFF);
	unsigned long e_entry = *(unsigned long *)((unsigned char *)elf_contents + E_ENTRY);
	unsigned long pagesz = 4096;
	int fd = open(filename, O_RDONLY);
	unsigned long load_base = 0;


	// If the ELF file is type dynamic we need to calculate the load_base for the virtual address and entry point
	if (e_type == ET_DYN) {
		unsigned long min_va = (unsigned long)-1;
		unsigned long max_va = 0;

		for (i = 0; i < nr; i++) {
			unsigned char *p = (unsigned char *)elf_contents + phoff + i * size;

			if (*(int *)p == 1) {
				unsigned long vaddr = *(unsigned long *)(p + P_VADDR);
				unsigned long memsz = *(unsigned long *)(p + P_MEMSZ);

				if (vaddr < min_va)
					min_va = vaddr;
				if (vaddr + memsz > max_va)
					max_va = vaddr + memsz;
			}
		}
		unsigned long map_start = min_va & ~(pagesz - 1);
		unsigned long map_end = (max_va + pagesz - 1) & ~(pagesz - 1);
		unsigned long map_size = map_end - map_start;

		void *pie = mmap(NULL, map_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (pie == MAP_FAILED)
		{
			perror("MAP_FAILED");
			exit(1);
		}

		load_base = (unsigned long)pie - map_start;
	}

	for (i = 0; i < nr; i++) {
		unsigned char *p = (unsigned char *)elf_contents + phoff + i * size;

		if (*(int *)p == 1) {
			unsigned long addr = *(unsigned long *)(p + P_VADDR);
			unsigned long offset = *(unsigned long *)(p + P_OFFSET);
			unsigned long filesz = *(unsigned long *)(p + P_FILESZ);
			unsigned long memsz = *(unsigned long *)(p + P_MEMSZ);
			uint32_t flags = *(uint32_t *)(p + P_FLAGS);

			unsigned long p_addr = addr & ~(pagesz - 1);
			unsigned long dif = addr - p_addr;

			p_addr += load_base;
			unsigned long offset2 = offset - dif;
			unsigned long map_len = (dif + filesz + pagesz - 1) & ~(pagesz - 1);
			int prot = get_prot(flags);
			//mmap((void *)p_addr, map_len, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_FIXED, fd, offset);
			void *map = mmap((void *)p_addr, map_len, prot, MAP_PRIVATE | MAP_FIXED, fd, offset2);
			if (map == MAP_FAILED)
			{
				perror("MAP_FAILED");
				exit(1);
			}

			if (memsz > filesz) {
				void *start = (void *)(p_addr + dif + filesz);
				size_t bss_size = memsz - filesz;
				unsigned long file_map_end = p_addr + map_len;

				size_t bss_file_page = 0;

				if ((unsigned long)start < file_map_end) {
					unsigned long end = (unsigned long)start + bss_size;
					unsigned long end_point = (end < file_map_end) ? end : file_map_end;

					bss_file_page = end_point - (unsigned long)start;
					memset(start, 0, bss_file_page);
				}
				size_t remaining = bss_size - bss_file_page;

				if (remaining > 0)
				{
					void *map = mmap((void *)file_map_end, remaining, prot, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
					if (map == MAP_FAILED)
					{
						perror("MAP_FAILED");
						exit(1);
					}
				}
			}
		}
	}

	// The creation of the stack pointer
	size_t marime_stiva = 1UL << 20;
	void *stiva = mmap(NULL, marime_stiva, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
	if (stiva == MAP_FAILED)
	{
		perror("MAP_FAILED");
		exit(1);
	}
	char *top = (char *)stiva + marime_stiva;

	// Pushing auxv on the stack
	top -= 16;
	unsigned char *random = (unsigned char *)top;

	for (int i = 0; i < 16; i++)
		random[i] = rand() & 0xff;
	unsigned long at_random = (unsigned long)random;

	void *sp = (unsigned char *)top;

	int num_env = 0;

	while (envp[num_env] != NULL)
		num_env++;

	sp -= sizeof(unsigned long);
	*(unsigned long *)sp = 0;
	sp -= sizeof(unsigned long);
	*(unsigned long *)sp = 0; //AT_NULL

	if (e_type == ET_DYN) {
		sp -= sizeof(unsigned long);
		*(unsigned long *)sp = load_base;
		sp -= sizeof(unsigned long);
		*(unsigned long *)sp = AT_BASE; //AT_BASE
	}

	sp -= sizeof(unsigned long);
	*(unsigned long *)sp = at_random;
	sp -= sizeof(unsigned long);
	*(unsigned long *)sp = AT_RANDOM; //AT_RANDOM

	unsigned long pvaddr = 0;

	for (i = 0; i < nr; i++) {
		unsigned char *p = (unsigned char *)elf_contents + phoff + i * size;

		if (*(int *)p == 6) {
			pvaddr = *(unsigned long *)(p + P_VADDR);
			break;
		}
	}
	if (pvaddr == 0) {
		for (i = 0; i < nr; i++) {
			unsigned char *p = (unsigned char *)elf_contents + phoff + i * size;

			if (*(int *)p == 1) {
				unsigned long addr = *(unsigned long *)(p + P_VADDR);
				unsigned long offset = *(unsigned long *)(p + P_OFFSET);
				unsigned long filesz = *(unsigned long *)(p + P_FILESZ);

				if (phoff >= offset && phoff < offset + filesz) {
					pvaddr = addr + (phoff - offset);
					break;
				}
			}
		}
	}
	sp -= sizeof(unsigned long);
	*(unsigned long *)sp = pvaddr + load_base;
	sp -= sizeof(unsigned long);
	*(unsigned long *)sp = AT_PHDR; //AT_PHDR

	sp -= sizeof(unsigned long);
	*(unsigned long *)sp = (unsigned long)size;
	sp -= sizeof(unsigned long);
	*(unsigned long *)sp = AT_PHENT; //AT_PHENT

	sp -= sizeof(unsigned long);
	*(unsigned long *)sp = (unsigned long)nr;
	sp -= sizeof(unsigned long);
	*(unsigned long *)sp = AT_PHNUM; //AT_PHNUM

	sp -= sizeof(unsigned long);
	*(unsigned long *)sp = 4096;
	sp -= sizeof(unsigned long);
	*(unsigned long *)sp = AT_PAGESZ; //AT_PAGESZ

	sp -= sizeof(unsigned long);
	*(unsigned long *)sp = e_entry + load_base;
	sp -= sizeof(unsigned long);
	*(unsigned long *)sp = AT_ENTRY; //AT_ENTRY

	// Pushing envp on the stack
	sp -= sizeof(char *);
	*(char **)sp = NULL;

	for (i = num_env - 1; i >= 0; i--) {
		sp -= sizeof(char *);
		*(unsigned long *)sp = (unsigned long)envp[i];
	}

	// Pushing argv on the stack
	sp -= sizeof(char *);
	*(char **)sp = NULL;

	for (i = argc - 1; i >= 0; i--) {
		sp -= sizeof(char *);
		*(unsigned long *)sp = (unsigned long)argv[i];
	}

	// Pushing argc on the stack
	sp -= sizeof(unsigned long);
	*(unsigned long *)sp = (unsigned long)(argc);

	// Entry point
	void (*entry)() = (void (*)())(e_entry + load_base);
	// Transfer control
	__asm__ __volatile__(
			"mov %0, %%rsp\n"
			"xor %%rbp, %%rbp\n"
			"jmp *%1\n"
			:
			: "r"(sp), "r"(entry)
			: "memory"
			);

	close(fd);
}

int main(int argc, char **argv, char **envp)
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <static-elf-binary>\n", argv[0]);
		exit(1);
	}

	load_and_run(argv[1], argc - 1, &argv[1], envp);
	return 0;
}
