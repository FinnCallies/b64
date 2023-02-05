#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include "crypt_util.h"


void print_b64(byte *b64, int len)
{
    for (int i = 0; i < len; i++) {
        printf("%c", b64[i]);
    }
    printf("\n");
}

void print_sextet(byte sextet)
{
    sextet = sextet % 64;
    for (int i = 0; i < 6; i++)
    {
        printf("%d", (sextet >> (5 - i)) & 1);
    }
    printf(" ");
}

void print_sextets(byte *sextets, int len)
{
    for (int i = 0; i < len; i++) {
        print_sextet(sextets[i]);
    }
    printf("\n");
}

int get_padding_size(int octet_cnt) 
{
    return (3 - (octet_cnt % 3)) % 3;
}

int get_padding_from_enc(byte *b64, int len)
{
    int padding = 0;
    for (int i = len - 1; i >= 0; i--) {
        if (b64[i] == '=') {
            padding++;
        } else {
            break;
        }
    }
    return padding;
}

int get_sextet_cnt(int octet_cnt)
{
    return (octet_cnt + get_padding_size(octet_cnt)) / 3 * 4;
}

int get_octet_cnt(byte *b64, int sextet_cnt)
{
    return (sextet_cnt) / 4 * 3 - get_padding_from_enc(b64, sextet_cnt);
}

void octets2sextets(byte *octets, byte *sextets, int len) {
    byte *octets_w_pad = (byte *)calloc(get_sextet_cnt(len), sizeof(byte));

    memcpy(octets_w_pad, octets, len);
    
    int i = 0;
    int j = 0;
    while (i < len) {
        j = i / 3;

        sextets[j * 4] = octets[i] >> 2;
        sextets[j * 4 + 1] = (octets[i] & 0x03) << 6 >> 2 | octets[i + 1] >> 4;
        sextets[j * 4 + 2] = (octets[i + 1] & 0x0f) << 2 | octets[i + 2] >> 6;
        sextets[j * 4 + 3] = octets[i + 2] & 0x3f;

        i += 3;
    }

    free(octets_w_pad);
}

void sextets2octets(byte *sextets, byte *octets, int len)
{
    byte *octets_w_pad = (byte *)calloc(len / 4 * 3, sizeof(byte));

    for (int i = 0; i < len / 4; i++)
    {
        octets_w_pad[i * 3] = sextets[i * 4] << 2 | sextets[i * 4 + 1] >> 4;
        octets_w_pad[i * 3 + 1] = (sextets[i * 4 + 1] & 0x0f) << 4 | sextets[i * 4 + 2] >> 2;
        octets_w_pad[i * 3 + 2] = (sextets[i * 4 + 2] & 0x03) << 6 | sextets[i * 4 + 3];
    }

    memcpy(octets, octets_w_pad, get_octet_cnt(sextets, len));
    
    free(octets_w_pad);
}

void encode_base64(byte *bytes, byte *base64, int len) {
    int padding = get_padding_size(len);
    int sextets_len = get_sextet_cnt(len);
    byte *sextets = (byte *)calloc(sextets_len, sizeof(byte));


    octets2sextets(bytes, sextets, len);
    for (int i = 0; i < sextets_len; i++) {
        if (sextets[i] < 26) {
            base64[i] = sextets[i] + 'A';
        } else if (sextets[i] < 52) {
            base64[i] = sextets[i] - 26 + 'a';
        } else if (sextets[i] < 62) {
            base64[i] = sextets[i] - 52 + '0';
        } else if (sextets[i] == 62) {
            base64[i] = '+';
        } else {
            base64[i] = '/';
        }
    }
    for (int i = 0; i < padding; i++) {
        base64[sextets_len - (i + 1)] = '=';
    }

    free(sextets);
}

void decode_base64(byte *base64, byte *bytes, int len)
{
    int padding = get_padding_from_enc(base64, len);
    byte *sextets = (byte *)calloc(len, sizeof(byte));

    for (int i = 0; i < padding; i++) {
        base64[len - i - 1] = 0;
    }

    for (int i = 0; i < len - padding; i++) {
        if (base64[i] == 43) {
            base64[i] = 62;
        } else if (base64[i] == 47) {
            base64[i] = 63;
        } else if (base64[i] > 47 && base64[i] < 58) {
            base64[i] = base64[i] - '0' + 52;
        } else if (base64[i] > 64 && base64[i] < 91) {
            base64[i] = base64[i] - 'A';
        } else if (base64[i] > 96 && base64[i] < 123) {
            base64[i] = base64[i] - 'a' + 26;
        } else {
            printf("ERROR: Invalid character in base64 string\n");
            exit(1);
        }
    }

    sextets2octets(base64, bytes, len);

    free(sextets);
}

void wtf_pls_fix()
{
    byte *plain = "Never gonna give you up, ...";
    int plain_len = 28;
    int enc_len = get_sextet_cnt(plain_len);
    byte *enc = (byte *)calloc(enc_len, sizeof(byte));

    printf("%s\n", plain); // some shit happening, idk, maybe https://www.youtube.com/watch?v=vusV4lF0Epo&t=309s&ab_channel=JacobSorber
    
    encode_base64(plain, enc, plain_len);

    print_b64(enc, enc_len);

    int dec_len = get_octet_cnt(enc, enc_len);
    byte *dec = (byte *)calloc(dec_len, sizeof(byte));

    decode_base64(enc, dec, enc_len);

    print_b64(dec, dec_len);


    free(enc);
    free(dec);
}

void b64_demo()
{
    int byte_cnt = 256;
    int sextet_cnt = get_sextet_cnt(byte_cnt);

    byte *plain = (byte *)calloc(byte_cnt, sizeof(byte));
    byte *encoded = (byte *)calloc(sextet_cnt, sizeof(byte));
    byte *decoded = (byte *)calloc(byte_cnt, sizeof(byte));
    
    gen_rndm_block(plain, byte_cnt);
    printf("PLAINTEXT: \n");
    print_bytes_line_break(plain, byte_cnt, 16);
    printf("\n");

    encode_base64(plain, encoded, byte_cnt);
    printf("ENCODED: \n");
    print_bytes_line_break(encoded, sextet_cnt, 16);
    printf("\n");

    decode_base64(encoded, decoded, sextet_cnt);
    printf("DECODED: \n");
    print_bytes_line_break(decoded, byte_cnt, 16);
    printf("\n");

    if (is_equal(plain, decoded, byte_cnt)) {
        printf("SUCCESS\n");
    } else {
        printf("FAIL\n");
    }


    // free some shit
    free(plain);
    free(encoded);
    free(decoded);
}

void str2bytes(char *str, byte *bytes, int len)
{
    for (int i = 0; i < len; i++) {
        bytes[i] = str[i];
    }
}

void bytes2str(byte *bytes, char *str, int len)
{
    for (int i = 0; i < len; i++) {
        str[i] = bytes[i];
    }
}

void parse_args(char **in, char **out, bool *enc, int *buffer_size, int argc, char *argv[])
{
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-e") == 0) {
            *enc = true;
        } else if (strcmp(argv[i], "-d") == 0) {
            *enc = false;
        } else if (strcmp(argv[i], "-f") == 0) {
            if (i + 1 < argc) {
                *in = argv[i + 1];
                i++;
            } else {
                printf("ERROR: No input file specified\n");
                exit(1);
            }
        } else if (strcmp(argv[i], "-o") == 0) {
            if (i + 1 < argc) {
                *out = argv[i + 1];
                i++;
            } else {
                printf("ERROR: No output file specified\n");
                exit(1);
            }
        } else if (strcmp(argv[i], "-b") == 0) {
            if (i + 1 < argc) {
                *buffer_size = atoi(argv[i + 1]);
                i++;
            } else {
                printf("ERROR: No buffer size specified\n");
                exit(1);
            }
        } else {
            printf("ERROR: Invalid argument\n");
            exit(1);
        }
    }
}

// b64 [-e/-d] -f input.txt -o output.txt -b 8192
void main(int argc, char *argv[])
{
    FILE *file;
    char *filename = NULL;
    char *buffer = NULL;
    bool encode = true;
    char *input_file = NULL;
    char *output_file = NULL;
    int buffer_size = 4096;



    parse_args(&input_file, &output_file, &encode, &buffer_size, argc, argv);
    if (input_file != NULL) {
        printf("%s\n", input_file);
    }
    if (output_file != NULL) {
        printf("%s\n", output_file);
    }
    printf("%d\n", buffer_size);
    if (buffer != NULL) {
        printf("%s\n", buffer);
    } else {
        buffer = (char *)calloc(buffer_size, sizeof(char));
        if (buffer == NULL) {
            fprintf(stderr, "ERROR: Failed to allocate memory\n");
            exit(1);
        }
    }

    
    
    file = fopen(input_file, "r");
    if (file == NULL) {
        fprintf(stderr, "ERROR: File \"%s\" not found\n", input_file);
        exit(1);
    }
    
    fread(buffer, buffer_size, 1, file);

    if (fclose(file) != 0) {
        fprintf(stderr, "ERROR: File \"%s\" not closed\n", input_file);
        exit(1);
    }


    int input_len = strlen(buffer);
    byte *input = (byte *)calloc(input_len, sizeof(byte));
    str2bytes(buffer, input, input_len);
    int output_len = 0;
    byte *output = NULL;

    if (encode)
    {
        output_len = get_sextet_cnt(input_len);
        output = (byte *)calloc(output_len, sizeof(byte));

        encode_base64(input, output, input_len);
    } else {
        output_len = get_octet_cnt(input, input_len);
        output = (byte *)calloc(output_len, sizeof(byte));

        decode_base64(input, output, input_len);
    }
    
    char *output_str = (char *)calloc(output_len, sizeof(char));
    bytes2str(output, output_str, output_len);


    file = fopen(output_file, "w");
    if (file == NULL) {
        fprintf(stderr, "ERROR: File \"%s\" not found\n", output_file);
        exit(1);
    }

    if (fwrite(output_str, output_len, 1, file) != 1) {
        fprintf(stderr, "ERROR: Failed to write to file \"%s\"\n", output_file);
        exit(1);
    }

    if (fclose(file) != 0) {
        fprintf(stderr, "ERROR: File \"%s\" not closed\n", output_file);
        exit(1);
    }
    

    free(input);
    free(output);
    free(output_str);
    free(buffer);
}
