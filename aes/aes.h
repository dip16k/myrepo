#ifndef AES_H
#define AES_H

extern void aesEncrypt(unsigned char input[16]);
extern void addRoundKey(unsigned char state[4][4],unsigned char round);
extern void shiftRows(unsigned char state[4][4]);
extern void mixColumn(unsigned char state[4][4]);
extern void subBytes(unsigned char state[4][4]);
extern void generateRoundKeys();

#endif
