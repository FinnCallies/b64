#ifndef BASE64_H_
#define BASE64_H_


#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "crypt_util.h"


void print_b64(byte *b64, int len);

void print_sextet(byte sextets);

void print_sextets(byte *sextets, int len);

int get_padding_size(int otet_cnt);

int get_padding_from_enc(byte *b64, int len);

int get_sextet_cnt(int octet_cnt);

int get_octet_cnt(byte *b64, int sextet_cnt);

void octets2sextets(byte *octets, byte *sextets, int len);

void encode_base64(byte *bytes, byte *base64, int len);

void decode_base64(byte *base64, byte *bytes, int len);

void wtf_pls_fix();

void b64_demo();

void str2bytes(char *str, byte *bytes, int len);

void bytes2str(byte *bytes, char *str, int len);

void print_help();

void parse_args(char **in, char **out, bool *enc, bool *from_file, bool *to_file, int *buffer_size, int argc, char *argv[]);

void main(int argc, char *argv[]);


#endif // BASE64_H_