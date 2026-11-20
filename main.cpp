#include <iostream>
#include <fstream>
#include <cstdint>
#include <array>
using namespace std;

int main(int argc, char* argv[]){
    if(argc != 2){
        cerr << "Usage: ps5 compat <file>" << endl;
        return 1;
    }

    ifstream file(argv[1], ios::binary);
    if(!file.is_open()){
        cerr << "Error: cannot open file\n";
        return 1;
    }

    array<uint8_t, 16> ident{};

    if(!file.read(reinterpret_cast<char *>(ident.data()), ident.size())){
        cerr<<"Error: file too small";
        return 1;
    }

    if(ident[0] != 0x7F || ident[1] != 'E' || ident[2] != 'L' || ident[3] != 'F'){
        cerr << "Error: ";
        return 1;
    }

    cout<<"Valid ELF signature\n";
    if(ident[4] == 1){
        cout<<"Arhitecture class: 32 biti\n";
    }
    else if(ident[4] == 2){
        cout<<"Arhitecture class: 64 biti\n";
    }
    else{
        cerr << "Error: invalid ELF signature\n";
        return 1;
    }
    if(ident[5] == 1){
        cout << "Endianness: Little Endian\n";
    }
    else if(ident[5] == 2){
        cout << "Endianness: Big Endian\n";
    }
    else{
        cerr<<"Unknown endianess";
        return 1;
    }
    return 0;
}