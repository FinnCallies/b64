#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include "crypt_util.h"


void print_bytes(byte *bytes, int len) 
{
    for (int i = 0; i < len; i++) {
        printf("%02x ", bytes[i]);
    }
    printf("\n");
}

void print_bytes_line_break(byte *bytes, int len, int line_len)
{
    for (int i = 0; i < len; i++) {
        printf("%02x ", bytes[i]);
        if ((i + 1) % line_len == 0) {
            printf("\n");
        }
    }
    printf("\n");
}

void print_byte_binary(byte b)
{
    for (int i = 7; i >= 0; i--) {
        printf("%d", (b >> i) & 1);
    }
    printf(" ");
}

void print_bytes_binary(byte *bytes, int len)
{
    for (int i = 0; i < len; i++) {
        print_byte_binary(bytes[i]);
    }
    printf("\n");
}

void print_bytes_by_block(byte *bytes, int len, int block_size)
{
    byte *block = (byte *)calloc(block_size, sizeof(byte));
    printf("\n");

    for (int i = 0; i < len / block_size; i++) {
        memcpy(block, bytes + block_size * (i + 1), block_size);
        printf("Block %d: ", i);
        print_bytes(block, block_size);
    }

    free(block);
}

void generate_rndm_ints(int *arr, int len, int max)
{
    srand(time(NULL));
    for (int i = 0; i < len; i++) {
        arr[i] = rand() % max;
    }
}

void generate_rndm_plaintext(byte *plaintext, int len)
{
    for (int i = 0; i < len; i++) {
        plaintext[i] = rand() % 256;
    }
}

void gen_rndm_block(byte *block, int len)
{
    srand(time(NULL));
    for (int i = 0; i < len; i++) {
        block[i] = rand() % 256;
    }
    // print_bytes(block, len);
}

bool is_equal(byte *block1, byte *block2, int len)
{
    for (int i = 0; i < len; i++) {
        if (block1[i] != block2[i]) {
            return false;
        }
    }
    return true;
}

void inc_counter(byte *counter, int len)
{
    if (counter[len - 1] == 255) {
        counter[len - 1] = 0;
        counter[len - 2]++;
    } else {
        counter[len - 1]++;
    }
    
}

void xor_bytes(byte *dest, byte *src1, byte *src2, int len)
{
    for (int i = 0; i < len; i++) {
        dest[i] = src1[i] ^ src2[i];
    }
}

int cnt_high_bits(byte *b, int size)
{
    int cnt = 0;
    for (int i = 0; i < size; i++) {
        for (int j = 0; j < 8; j++) {
            if ((b[i] >> (7 - j)) & 1) {
                cnt++;
            }
        }
    }
    return cnt;
}
