#ifndef GENERATORS_H
#define GENERATORS_H

void generate_IV(unsigned char* IV);
void generate_salt(unsigned char* IV);
void generate_token(unsigned char* token);
unsigned long long generate_one_long_long();


#endif
