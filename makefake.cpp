#include <fstream>
#include <cstdint>
using namespace std;

#pragma pack(push, 1)
struct Elf64_Ehdr {
    uint8_t  e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

struct Elf64_Phdr {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
};
#pragma pack(pop)

int main() {
    // 1. Headerul ELF (cartea de identitate)
    Elf64_Ehdr h{};
    h.e_ident[0] = 0x7F; h.e_ident[1] = 'E'; h.e_ident[2] = 'L'; h.e_ident[3] = 'F';
    h.e_ident[4] = 2;    // 64 biti
    h.e_ident[5] = 1;    // little endian
    h.e_ident[6] = 1;    // versiune
    h.e_type      = 2;        // executabil
    h.e_machine   = 0x3E;     // x86-64
    h.e_version   = 1;
    h.e_entry     = 0x400078; // entry point
    h.e_phoff     = 64;       // program headers incep dupa header
    h.e_ehsize    = 64;
    h.e_phentsize = 56;
    h.e_phnum     = 1;
    h.e_shentsize = 64;

    // 2. Un singur program header: "incarca tot fisierul la 0x400000"
    Elf64_Phdr p{};
    p.p_type   = 1;         // PT_LOAD
    p.p_flags  = 5;         // R + X
    p.p_offset = 0;
    p.p_vaddr  = 0x400000;
    p.p_paddr  = 0x400000;
    p.p_filesz = 126;
    p.p_memsz  = 126;
    p.p_align  = 0x1000;

    // 3. Programul: mov eax, 42 ; ret
    uint8_t code[] = { 0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3 };

    ofstream f("fake.elf", ios::binary);
    f.write(reinterpret_cast<char*>(&h), sizeof(h));
    f.write(reinterpret_cast<char*>(&p), sizeof(p));
    f.write(reinterpret_cast<char*>(code), sizeof(code));
    return 0;
}