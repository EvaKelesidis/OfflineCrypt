#ifndef PASSWORD_FUNCTIONS_H
#define PASSWORD_FUNCTIONS_H

int check_password(unsigned char* password, size_t length, unsigned char* key, int get_iv);
int update_password(unsigned char* password, size_t length);
int encrypt_token(unsigned char key[], unsigned char iv[], unsigned char salt[]);
int encrypt_key(unsigned char key[], unsigned char iv[], unsigned char salt[], unsigned char* privatekey, size_t length);

#endif // PASSWORD_FUNCTIONS_H
