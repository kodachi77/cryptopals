#ifndef UTILS_H__
#define UTILS_H__

#ifdef __GNUC__
#define __STDC_WANT_LIB_EXT1__ 1
#define __STDC_WANT_LIB_EXT2__ 1
#endif

#ifdef _MSC_VER
#define _CRT_NONSTDC_NO_DEPRECATE 1
#endif

#include <stddef.h>

#define ARRAY_SIZE( arr ) ( sizeof( arr ) / sizeof( ( arr )[0] ) )

#define ERR_OK                  0
#define ERR_INVALID_ARGUMENT    -1
#define ERR_INSUFFICIENT_BUFFER -2
#define ERR_INSUFFICIENT_MEMORY -3
#define ERR_FILE_ERROR          -4
#define ERR_AES_ERROR           -5
#define ERR_INVALID_PADDING     -6
#define ERR_GENERIC_ERROR       -7

#define MODE_BINARY 0
#define MODE_TEXT   1

int cp_randint( int n );
int cp_generate_random_string( char* dst, size_t dst_len, int seq_len );

int  cp_hex2int( char ch );
char cp_int2hex( int i );

/* we have 128-bit keys */
#define AES_KEY_SIZE   16
#define AES_BLOCK_SIZE 16
#define AES_NUM_ROUNDS 10

/* 
 * All the functions below allocate buffer large enough for the conversion. 
 * The caller is responsible for freeing this buffer. 
 */
int cp_hex2bytes( char** dst, size_t* dst_len, const char* hex_data, size_t hex_len, int mode );
int cp_bytes2hex( char** dst, size_t* dst_len, const char* byte_data, size_t byte_len, int mode );

int cp_base64_encode( char** dst, size_t* dst_len, const char* src, size_t src_len, int mode );
int cp_base64_decode( char** dst, size_t* dst_len, const char* src, size_t src_len, int mode );

int cp_break_single_char_xor( char* dst, size_t dst_len, char* out_key, double* out_score );

int cp_block_xor( char* dst, const char* src, size_t len );
int cp_repeating_xor( char* dst, size_t dst_len, const char* key, size_t key_len );

int cp_pkcs7_pad( char** dst, size_t* dst_len, const char* src, size_t src_len, size_t blk_len, int mode );
int cp_pkcs7_unpad( char** dst, size_t* dst_len, const char* src, size_t src_len, int mode );

int cp_pkcs7_pad_inplace( size_t* padded_len, char* dst, size_t dst_len, size_t curr_offset, size_t blk_len );

int cp_aes_ecb_decrypt( char** dst, size_t* dst_len, const char* src, size_t src_len, const char* key, size_t key_len,
                        int mode );

int cp_aes_ecb_encrypt( char** dst, size_t* dst_len, const char* src, size_t src_len, const char* key, size_t key_len,
                        int mode );

int cp_aes_cbc_encrypt( char** dst, size_t* dst_len, const char* data, size_t data_len, const char* key, size_t key_len,
                        const char* iv, size_t iv_len, int mode );

int cp_aes_cbc_decrypt( char** dst, size_t* dst_len, const char* data, size_t data_len, const char* key, size_t key_len,
                        const char* iv, size_t iv_len, int mode );

int cp_count_ecb_repetitions( const char* src, size_t src_len, size_t block_size );

/* 
 * File utilities. 
 */
int cp_read_all( char** dst, size_t* dst_len, const char* filename, int mode );

typedef void ( *cp_line_callback )( const char* line, size_t len, void* arg, int line_idx );

int cp_read_lines( const char* filename, cp_line_callback on_line, void* arg );

void cp_dump_bytes( const char* msg, const char* buf, size_t len );

#endif