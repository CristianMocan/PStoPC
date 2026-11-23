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

struct ImportEntry {
    uint64_t slot_vaddr;
    char name[32];
}
#pragma pack(pop)

int main() {
    const uint64_t BASE = 0x400000;
    
    // 3. Programul: mov eax, 42 ; ret
    uint8_t code[] = {
        0x48, 0x83, 0xEC, 0x28,                    // sub rsp, 40
        0xB9, 0x2A, 0x00, 0x00, 0x00,              // mov ecx, 42
        0xFF, 0x15, 0x15, 0x00, 0x00, 0x00,        // call [rip+21]  -> slot
        0xB9, 0x64, 0x00, 0x00, 0x00,              // mov ecx, 100
        0xFF, 0x15, 0x0A, 0x00, 0x00, 0x00,        // call [rip+10]  -> slot
        0x48, 0x83, 0xC4, 0x28,                    // add rsp, 40
        0xB8, 0x07, 0x00, 0x00, 0x00,              // mov eax, 7
        0xC3                                       // ret
    };

    uint8_t slot[8] = {};

    const uint64_t codeOff = sizeof(Elf64_Ehdr) + 2 * sizeof(Elf64_Phdr); // 176
    const uint64_t slotOff = codeOff + sizeof(code); // 176 + 36 = 212
    const uint64_t importOff = slotOff + sizeof(slot); // 212 + 8 = 220
    const uint64_t total = importOff + sizeof(ImportEntry); // 220 + 8 + 32 = 260

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
    Elf64_Phdr load{};
    load.p_type   = 1;         // PT_LOAD
    load.p_flags  = 5;         // R + X
    load.p_offset = 0;
    load.p_vaddr  = BASE;
    load.p_paddr  = BASE;
    load.p_filesz = total;
    load.p_memsz  = total;
    load.p_align  = 0x1000;

    Elf64_Phdr imp{};
    imp.p_type = 0x61000001;
    imp.p_flags = 4;
    imp.p_offset = importOff;
    imp.p_filesz = sizeof(ImportEntry);
    imp.p_memsz = sizeof(ImportEntry);
    imp.p_align = 1;

    ImportEntry e{};
    e.slot_vaddr = BASE + slotOff;
    strncpy(e.name, "print_int", sizeof(e.name) - 1);

    ofstream f("fake.elf", ios::binary);
    f.write(reinterpret_cast<char*>(&h), sizeof(h));
    f.write(reinterpret_cast<char*>(&load), sizeof(load));
    f.write(reinterpret_cast<char*>(&imp), sizeof(imp));
    f.write(reinterpret_cast<char*>(code), sizeof(code));
    f.write(reinterpret_cast<char*>(slot), sizeof(slot));
    f.write(reinterpret_cast<char*>(&e), sizeof(e));
    return 0;
}