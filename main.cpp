#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>
#include <cstring>
#include <array>
#include <windows.h>
#include <map>
#include <string>
using namespace std;
#pragma pack(push, 1)
struct Elf64_Ehdr{
    uint8_t e_ident[16];
    uint16_t e_type;       // 2 = executabil, 3 = shared/PIE
    uint16_t e_machine;    // 0x3E = x86-64
    uint32_t e_version;
    uint64_t e_entry;      // adresa unde incepe executia
    uint64_t e_phoff;      // offset tabel program headers
    uint64_t e_shoff;      // offset tabel section headers
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;  // marimea unui program header
    uint16_t e_phnum;      // cate program headers
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
    char     name[32];
};
#pragma pack(pop)

const uint32_t PT_LOAD = 1;
const uint64_t PAGE = 0x1000;
const uint32_t PT_IMPORTS = 0x61000001;
uint64_t alignDown(uint64_t v){
    return v & ~(PAGE - 1);
}

uint64_t alignUp(uint64_t v){
    return (v + PAGE - 1) & ~(PAGE - 1);
}

bool readFile(const char* path, vector<uint8_t>& out){
    ifstream f(path, ios::binary | ios::ate);
    if(!f) return false;
    streamsize n = f.tellg();
    f.seekg(0);
    out.resize(static_cast<size_t>(n));
    return bool(f.read(reinterpret_cast<char*>(out.data()),n));
}

DWORD toWinProt(uint32_t f){
    bool w = f & 2, x = f & 1, r = f & 4;
    if(x) return w ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
    if(w) return PAGE_READWRITE;
    if(r) return PAGE_READONLY;
    return PAGE_NOACCESS;
}

void host_print(int x){
    cout<< dec <<"Guest says: " << x  << "\n";
}

string flagsStr(uint32_t f){
    string s;
    s += (f & 4) ? 'R' : '-';
    s += (f & 2) ? 'W' : '-';
    s += (f & 1) ? 'X' : '-';
    return s;
}

int main(int argc, char* argv[]){
    if(argc < 2 || argc > 3){
        cerr << "Usage: anyps5 <file> [--run]\n";
        return 1;
    }
    bool run = (argc == 3 && string(argv[2]) == "--run");
    vector<uint8_t> data;

    if(!readFile(argv[1], data)){
        cerr << "Error: cannot read file\n";
        return 1;
    }
    if(data.size() < sizeof(Elf64_Ehdr)){
        cerr << "Error: file too small\n";
        return 1;
    }

    Elf64_Ehdr h{};
    memcpy(&h, data.data(), sizeof(h));

    if (h.e_ident[0] != 0x7F || h.e_ident[1] != 'E' ||
        h.e_ident[2] != 'L'  || h.e_ident[3] != 'F') {
        cerr << "Error: not an ELF file\n"; return 1;
    }
    if (h.e_ident[4] != 2)   { cerr << "Error: not 64-bit\n"; return 1; }
    if (h.e_ident[5] != 1)   { cerr << "Error: not little endian\n"; return 1; }
    if (h.e_machine != 0x3E) { cerr << "Error: not x86-64\n"; return 1; }
    cout << "Valid ELF signature\n";


    if(h.e_phentsize != sizeof(Elf64_Phdr)){
        cerr<<"Error: bad penthsize\n";
        return 1;
    }
    if(h.e_phnum == 0){
        cerr<<"Error: no program headers\n";
        return 1;
    }
    size_t phBytes = h.e_phnum * sizeof(Elf64_Phdr);
    if(h.e_phoff > data.size() || phBytes > data.size() - h.e_phoff){
        cerr << "Error: program headers outside file\n"; return 1;
    }

    vector<Elf64_Phdr> ph(h.e_phnum);
    memcpy(ph.data(), data.data() + h.e_phoff, phBytes);

    uint64_t lo = UINT64_MAX, hi = 0;
    for(const auto& p : ph){
        if(p.p_type != PT_LOAD) continue;
        if(p.p_filesz > p.p_memsz){
            cerr<<"Error: filesz > memsize\n";
            return 1;
        }
        if(p.p_offset > data.size() || p.p_filesz > data.size() - p.p_offset){
            cerr<<"Error: segment data outside file\n";
            return 1;
        }
        if(p.p_vaddr > 0x7FFFFFFFFFFFULL || p.p_memsz > 0x40000000ULL){
            cerr << "Error: segment address/size unreasonable";
            return 1;
        }
        if (p.p_vaddr < lo) lo = p.p_vaddr;
        if (p.p_vaddr + p.p_memsz > hi) hi = p.p_vaddr + p.p_memsz;
    }
    if(lo == UINT64_MAX){
        cerr << "Error: no load segments\n"; return 1;
    }

    lo = alignDown(lo);
    hi = alignUp(hi);
    if(hi - lo > 0x40000000ULL){
        cerr << "Error: image too large\n";
        return 1;
    }

    size_t total = static_cast<size_t>(hi-lo);
    uint8_t* mem = static_cast<uint8_t*>(
        VirtualAlloc(nullptr, total, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)
    );
    if(!mem){
        cerr<<"Error: VirtualAlloc failed (" << GetLastError() << ")\n";
        return 1;
    }
    uintptr_t base = reinterpret_cast<uintptr_t>(mem) - lo;

    for(const auto &p : ph){
        if(p.p_type != PT_LOAD) continue;
        memcpy(reinterpret_cast<void*>(base + p.p_vaddr), data.data() + p.p_offset, p.p_filesz);
    }

    cout << hex;
    for(const auto&p : ph){
        if(p.p_type != PT_LOAD){
            continue;
        }
        uint64_t s = alignDown(p.p_vaddr);
        uint64_t e = alignUp(p.p_vaddr + p.p_memsz);
        DWORD old;
        if(!VirtualProtect(reinterpret_cast<void*>(base + s), static_cast<SIZE_T>(e - s), toWinProt(p.p_flags), &old)){
            cerr << "Error: VirtualProtect failed\n"; return 1;
        }
        cout << "Loaded " << flagsStr(p.p_flags) << "  vaddr=0x" << p.p_vaddr << " -> real=0x" << (base + p.p_vaddr)
            << " size=0x" << p.p_memsz << "\n";
    }
    bool entryOk = false;
    for(const auto& p: ph){
        if (p.p_type == PT_LOAD && (p.p_flags & 1) &&
            h.e_entry >= p.p_vaddr && h.e_entry < p.p_vaddr + p.p_memsz) {
            entryOk = true;
        }
    }
    if (!entryOk) {
        cerr << "Error: entry point not inside an executable segment\n";
        return 1;
    }
    cout << "Entry: vaddr=0x" << h.e_entry << " -> real=0x" << (base + h.e_entry) << "\n";

    if(run){
        using EntryFn = int(*)(void(*)(int));
        EntryFn fn = reinterpret_cast<EntryFn>(base + h.e_entry);
        int r = fn(host_print);
        cout<<dec<<"Guest code returned: " << r << "\n";
    }
    VirtualFree(mem, 0, MEM_RELEASE);
    return 0;
}