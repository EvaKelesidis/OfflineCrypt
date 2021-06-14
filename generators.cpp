#include <immintrin.h>
#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <stdint.h>
#include <string>
#include <iostream>
#include <fstream>

#include "generators.h"

using namespace std;

class CPUID {
    uint32_t regs[4];

    public:
        explicit CPUID(unsigned i)
    {
            #ifdef _WIN32
                __cpuid((int *)regs, (int)i);

            #else
                asm volatile
                  ("cpuid" : "=a" (regs[0]), "=b" (regs[1]), "=c" (regs[2]), "=d" (regs[3])
                   : "a" (i), "c" (0));

                    // ECX is set to zero for CPUID function 4
            #endif
  }
    const uint32_t &EAX() const {return regs[0];}
    const uint32_t &EBX() const {return regs[1];}
    const uint32_t &ECX() const {return regs[2];}
    const uint32_t &EDX() const {return regs[3];}

};

unsigned long long generate_one_long_long()
{
    CPUID cpuID(0);

    string vendor = "";
    vendor += string((const char *)&cpuID.EBX(), 4);
    vendor += string((const char *)&cpuID.EDX(), 4);
    vendor += string((const char *)&cpuID.ECX(), 4);


    unsigned long long result = 0ULL;
    int rc;

    #ifdef __linux__

        unsigned long long int random_value = 0; //Declare value to store data into
        size_t size = sizeof(random_value); //Declare size of data
        ifstream urandom("/dev/urandom", ios::in|ios::binary); //Open stream
        if(urandom) //Check if stream is open
        {
            urandom.read(reinterpret_cast<char*>(&random_value), size); //Read from urandom
            if(urandom) //Check if stream is ok, read succeeded
               return random_value;
            else //Read failed
            {
                std::cerr << "Failed to read from /dev/urandom" << std::endl;
                return -1;
            }
            urandom.close(); //close stream
        }
        else //Open failed
        {
            std::cerr << "Failed to open /dev/urandom" << std::endl;
            return -1;
        }

       #endif

}


void generate_IV(unsigned char* IV)
{
    unsigned long long result = generate_one_long_long();

    for(int j = 0; j < 8; j++)
        IV[j] = (result >> (8*j))&0xFF;

    result = generate_one_long_long();

    for(int j = 0; j < 8; j++)
        IV[j + 8] = (result >> (8*j))&0xFF;
}


void generate_salt(unsigned char* salt)
{
    unsigned long long result;
    for(int i = 0; i < 64; i = i + 8){
        result = generate_one_long_long();
        for(int j = 0; j < 8; j++)
            salt[i + j] = (result >> (8*j))&0xFF;
    }
}

/*
void generate_token(unsigned char* token)
{
    unsigned long long result;
    for(int i = 0; i < 128; i = i + 8){
        result = generate_one_long_long();
        for(int j = 0; j < 8; j++)
            token[i + j] = (result >> (8*j))&0xFF;
    }

}
*/
