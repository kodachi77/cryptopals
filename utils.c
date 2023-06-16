#include "utils.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define LTC_NO_PROTOTYPES
#include <tomcrypt.h>

#if defined(__GNUC__) && !__STDC_LIB_EXT1__

#include <sys/errno.h>

typedef int errno_t;

errno_t
fopen_s( FILE** f, const char* name, const char* mode )
{
    errno_t ret = 0;
    assert( f );
    *f = fopen( name, mode );
    if( !*f ) ret = errno;
    return ret;
}
#endif


int
cp_randint( int n )
{
    /* See https://stackoverflow.com/questions/822323/how-to-generate-a-random-int-in-c */
    int r, end;
    assert( n > 0 && n <= RAND_MAX );
    if( ( n - 1 ) == RAND_MAX ) { return rand(); }
    else
    {
        end = RAND_MAX / n;
        end *= n;

        while( ( r = rand() ) >= end )
            ;

        return r % n;
    }
}

int
cp_generate_random_string( char* dst, size_t dst_len, int seq_len )
{
    int i;
    assert( dst && dst_len );
    assert( dst_len >= seq_len );
    if( !dst || !dst_len || dst_len < seq_len ) return ERR_INVALID_ARGUMENT;

    /* let's use base64 symbol set */
    static const char* s_lookup = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/";

    for( i = 0; i < seq_len; i++ ) dst[i] = s_lookup[cp_randint( 64 )];

    return ERR_OK;
}

int
cp_hex2int( char ch )
{
    assert( ( ch >= '0' && ch <= '9' ) || ( ch >= 'A' && ch <= 'F' ) || ( ch >= 'a' && ch <= 'f' ) );

    if( ch >= '0' && ch <= '9' )
        return ch - '0';
    else if( ch >= 'a' && ch <= 'f' )
        return 10 + ch - 'a';
    else if( ch >= 'A' && ch <= 'F' )
        return 10 + ch - 'A';
    else
        return ERR_INVALID_ARGUMENT;
}

char
cp_int2hex( int i )
{
    assert( i >= 0 && i <= 15 );

    if( i >= 0 && i <= 9 )
        return '0' + i;
    else if( i >= 10 && i <= 15 )
        return 'a' + i - 10;
    else
        return ERR_INVALID_ARGUMENT;
}

int
cp_hex2bytes( char** dst, size_t* dst_len, const char* hex_data, size_t hex_len, int mode )
{
    size_t      i, byte_len;
    char *      buffer, *p;
    const char* s;

    assert( dst && dst_len );
    assert( hex_data && hex_len && hex_len % 2 == 0 );
    assert( mode == MODE_BINARY || mode == MODE_TEXT );

    if( !dst || !dst_len || !hex_data || !hex_len || hex_len % 2 || !( mode == MODE_BINARY || mode == MODE_TEXT ) )
    {
        return ERR_INVALID_ARGUMENT;
    }

    byte_len = hex_len / 2;
    buffer   = (char*) malloc( byte_len + mode );
    if( !buffer ) { return ERR_INSUFFICIENT_MEMORY; }

    for( i = 0, s = hex_data, p = buffer; i < hex_len; i += 2 )
    {
        *p++ = ( cp_hex2int( *s++ ) << 4 ) | cp_hex2int( *s++ );
    }
    if( mode == MODE_TEXT ) { *p = 0; }

    assert( byte_len == p - buffer );
    *dst     = buffer;
    *dst_len = byte_len;

    return ERR_OK;
}

int
cp_bytes2hex( char** dst, size_t* dst_len, const char* byte_data, size_t byte_len, int mode )
{
    size_t      i, hex_len;
    char *      buffer, *p;
    const char* s;

    assert( dst && dst_len );
    assert( byte_data && byte_len );
    assert( mode == MODE_BINARY || mode == MODE_TEXT );

    if( !byte_data || !byte_len || !dst || !dst_len ) { return ERR_INVALID_ARGUMENT; }

    hex_len = 2 * byte_len + ( mode == MODE_TEXT ? 1 : 0 );
    buffer  = (char*) malloc( hex_len );
    if( !buffer ) { return ERR_INSUFFICIENT_MEMORY; }

    for( i = 0, s = byte_data, p = buffer; i < byte_len; i++ )
    {
        *p++ = cp_int2hex( ( *s & 0xF0 ) >> 4 );
        *p++ = cp_int2hex( *s++ & 0x0F );
    }
    if( mode == MODE_TEXT ) { *p = 0; }

    *dst     = buffer;
    *dst_len = hex_len;

    return ERR_OK;
}

int
cp_base64_encode( char** dst, size_t* dst_len, const char* src, size_t src_len, int mode )
{
    size_t      i, n, n_3bytes;
    char *      buffer, *p;
    const char* s;
    int         ch1, ch2, ch3;

    static const char* s_base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    assert( dst && dst_len );
    assert( src && src_len );
    assert( mode == MODE_BINARY || mode == MODE_TEXT );

    if( !dst || !dst_len || !src || !src_len || !( mode == MODE_BINARY || mode == MODE_TEXT ) )
    {
        return ERR_INVALID_ARGUMENT;
    }

    n = src_len / 3 + ( src_len % 3 != 0 );
    n *= 4;

    buffer = (char*) malloc( n + mode );
    if( !buffer ) { return ERR_INSUFFICIENT_MEMORY; }

    n_3bytes = ( src_len / 3 ) * 3;
    for( i = 0, s = src, p = buffer; i < n_3bytes; i += 3 )
    {
        ch1 = *s++;
        ch2 = *s++;
        ch3 = *s++;

        *p++ = s_base64Chars[( ch1 >> 2 ) & 0x3F];
        *p++ = s_base64Chars[( ( ( ch1 & 0x3 ) << 4 ) + ( ch2 >> 4 ) ) & 0x3F];
        *p++ = s_base64Chars[( ( ( ch2 & 0xF ) << 2 ) + ( ch3 >> 6 ) ) & 0x3F];
        *p++ = s_base64Chars[ch3 & 0x3F];
    }

    if( i < src_len )
    {
        ch1 = *s++;
        ch2 = ( ( i + 1 ) < src_len ) ? *s++ : 0;

        *p++ = s_base64Chars[( ch1 >> 2 ) & 0x3F];
        *p++ = s_base64Chars[( ( ( ch1 & 0x3 ) << 4 ) + ( ch2 >> 4 ) ) & 0x3F];

        if( i + 1 < src_len ) { *p++ = s_base64Chars[( ( ch2 & 0xF ) << 2 ) & 0x3F]; }
        else
        {
            *p++ = '=';
        }

        *p++ = '=';
    }
    if( mode == MODE_TEXT ) { *p = 0; }

    assert( n == p - buffer );

    *dst     = buffer;
    *dst_len = n;

    return ERR_OK;
}

int
cp_base64_decode( char** dst, size_t* dst_len, const char* src, size_t src_len, int mode )
{
    size_t       i, n;
    unsigned int x;
    unsigned     n_sixtets      = 0;
    unsigned     padding        = 0;
    int          spaces_present = 0;
    char *       buffer, *p;

    static const unsigned char s_base64Indices[256] = {
        255, 255, 255, 255, 255, 255, 255, 255, 255, 253, 253, 255, 255, 253, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 253, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 62,
        255, 255, 255, 63,  52,  53,  54,  55,  56,  57,  58,  59,  60,  61,  255, 255, 255, 254, 255, 255, 255, 0,
        1,   2,   3,   4,   5,   6,   7,   8,   9,   10,  11,  12,  13,  14,  15,  16,  17,  18,  19,  20,  21,  22,
        23,  24,  25,  255, 255, 255, 255, 255, 255, 26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,  37,  38,
        39,  40,  41,  42,  43,  44,  45,  46,  47,  48,  49,  50,  51,  255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255 };

    assert( dst && dst_len );
    assert( src && src_len );
    assert( mode == MODE_BINARY || mode == MODE_TEXT );

    if( !dst || !dst_len || !src || !src_len || !( mode == MODE_BINARY || mode == MODE_TEXT ) )
    {
        return ERR_INVALID_ARGUMENT;
    }

    // we're not going to implement overly complicated decoding
    // we're just going to skip new line characters as well as spaces

    for( i = 0, n = 0; i < src_len; i++ )
    {
        if( src[i] == '\r' || src[i] == '\n' || src[i] == ' ' ) { continue; }

        if( src[i] == '=' )
        {
            if( ++padding > 2 ) { return ERR_INVALID_ARGUMENT; }
        }
        n++;
    }

    n = ( ( n * 6 ) + 7 ) >> 3;
    n -= padding;

    buffer = (char*) malloc( n + mode );
    if( !buffer ) { return ERR_INSUFFICIENT_MEMORY; }

    padding = 0;
    for( x = 0, p = buffer; i > 0; i--, src++ )
    {
        if( *src == '\r' || *src == '\n' || *src == ' ' ) { continue; }

        x = x << 6;
        if( *src == '=' ) { ++padding; }
        else
        {
            x |= s_base64Indices[*src];
        }

        if( ++n_sixtets == 4 )
        {
            n_sixtets = 0;
            *p++      = ( x >> 16 ) & 0xff;
            if( padding <= 1 ) { *p++ = ( x >> 8 ) & 0xff; }
            if( padding <= 0 ) { *p++ = ( x & 0xff ); }
        }
    }

    if( mode == MODE_TEXT ) { *p = 0; }
    assert( n == p - buffer );

    *dst     = buffer;
    *dst_len = n;

    return ERR_OK;
}

static inline double
get_english_letter_score( int ch )
{
    // taken from http://www.practicalcryptography.com/cryptanalysis/letter-frequencies-various-languages/english-letter-frequencies/
    static const double s_englishLetterFrequencies[] = { 8.55, 1.60, 3.16, 3.87, 12.10, 2.18, 2.09, 4.96, 7.33,
                                                         0.22, 0.81, 4.21, 2.53, 7.17,  7.47, 2.07, 0.10, 6.33,
                                                         6.73, 8.94, 2.68, 1.06, 1.83,  0.19, 1.72, 0.11 };
    if( ch >= 'a' && ch <= 'z' )
        ch = ch - 'a';
    else if( ch >= 'A' && ch <= 'Z' )
        ch = ch - 'A';
    else if( ch == ' ' )
        // this is taken from https://mathstats.uncg.edu/sites/pauli/112/HTML/secfrequency.html
        return 18.85;
    else
        return 0.0;

    return s_englishLetterFrequencies[ch];
}

int
cp_break_single_char_xor( char* dst, size_t dst_len, char* out_key, double* out_score )
{
    size_t i, j;

    assert( dst && dst_len );
    if( !dst || !dst_len ) return ERR_INVALID_ARGUMENT;

    char   key_candidate = 0;
    double max_score     = 0.0;
    for( i = 0; i < 256; ++i )
    {
        double score = 0.0;
        for( j = 0; j < dst_len; ++j ) { score += get_english_letter_score( dst[j] ^ (int) i ); }
        if( score > max_score )
        {
            max_score     = score;
            key_candidate = (char) i;
        }
    }
    for( i = 0; i < dst_len; ++i ) { dst[i] ^= key_candidate; }

    if( out_key ) *out_key = key_candidate;
    if( out_score ) *out_score = max_score;

    return ERR_OK;
}

int
cp_pkcs7_pad( char** dst, size_t* dst_len, const char* src, size_t src_len, size_t blk_len, int mode )
{
    size_t len, pad_len;
    char*  buffer;

    assert( dst && dst_len );
    assert( src && src_len && blk_len );
    assert( mode == MODE_BINARY || mode == MODE_TEXT );

    if( !dst || !dst_len || !src || !src_len || !blk_len || !( mode == MODE_BINARY || mode == MODE_TEXT ) )
    {
        return ERR_INVALID_ARGUMENT;
    }

    pad_len = src_len % blk_len ? blk_len - src_len % blk_len : 0;
    len     = src_len + pad_len;

    buffer = (char*) malloc( len + mode );
    if( !buffer ) { return ERR_INSUFFICIENT_MEMORY; }

    memcpy( buffer, src, src_len );
    if( pad_len ) { memset( buffer + src_len, (int) pad_len, pad_len ); }

    if( mode == MODE_TEXT ) { buffer[blk_len] = 0; }
    *dst     = buffer;
    *dst_len = len;

    return ERR_OK;
}

int
cp_pkcs7_pad_inplace( size_t* padded_len, char* dst, size_t dst_len, size_t curr_offset, size_t blk_len )
{
    size_t pad_len;

    assert( padded_len );
    assert( dst && dst_len );
    assert( blk_len );

    if( !padded_len || !dst || !dst_len || !blk_len ) return ERR_INVALID_ARGUMENT;

    pad_len = curr_offset % blk_len ? blk_len - curr_offset % blk_len : 0;
    assert( curr_offset + pad_len <= dst_len );
    if( curr_offset + pad_len > dst_len ) return ERR_INVALID_ARGUMENT;

    if( pad_len ) { memset( dst + curr_offset, (int) pad_len, pad_len ); }
    *padded_len = curr_offset + pad_len;

    return ERR_OK;
}

int
cp_pkcs7_unpad( char** dst, size_t* dst_len, const char* src, size_t src_len, int mode )
{
    size_t i, len, pad_len = 0, n = 1;
    char*  buffer = NULL;
    int    ret    = ERR_OK;

    assert( dst && dst_len );
    assert( src && src_len );
    assert( mode == MODE_BINARY || mode == MODE_TEXT );

    if( !dst || !dst_len || !src || !src_len || !( mode == MODE_BINARY || mode == MODE_TEXT ) )
    {
        return ERR_INVALID_ARGUMENT;
    }

    pad_len = src[src_len - 1];
    if( pad_len < src_len )
    {
        for( i = src_len - 1; i >= src_len - pad_len; i-- )
        {
            if( src[i] == src[i - 1] )
                ++n;
            else
                break;
        }
        if( n != pad_len )
        {
            pad_len = 0;
            ret     = ERR_INVALID_PADDING;
        }
    }
    else
    {
        pad_len = 0;
        ret     = ERR_INVALID_PADDING;
    }

    len    = src_len - pad_len;
    buffer = (char*) malloc( len + mode );
    if( !buffer ) { return ERR_INSUFFICIENT_MEMORY; }

    memcpy( buffer, src, len );

    if( mode == MODE_TEXT ) { buffer[len] = 0; }

    *dst     = buffer;
    *dst_len = len;

    return ret;
}

int
cp_aes_ecb_decrypt( char** dst, size_t* dst_len, const char* src, size_t src_len, const char* key, size_t key_len,
                    int mode )
{
    symmetric_ECB ecb;
    int           cipher, ret;
    char*         buffer = NULL;

    assert( dst && dst_len );
    assert( src && src_len );
    assert( key && key_len );
    assert( mode == MODE_BINARY || mode == MODE_TEXT );

    if( !dst || !dst_len || !src || !src_len || !key || !key_len || !( mode == MODE_BINARY || mode == MODE_TEXT ) )
    {
        return ERR_INVALID_ARGUMENT;
    }

    cipher = register_cipher( &aes_desc );
    if( cipher == -1 ) return ERR_AES_ERROR;

    ret = ecb_start( cipher, key, (int) key_len, AES_NUM_ROUNDS, &ecb );
    if( ret != CRYPT_OK ) return ERR_AES_ERROR;

    buffer = (char*) malloc( src_len + mode );
    if( !buffer ) { ret = ERR_INSUFFICIENT_MEMORY; }
    else
    {
        ret = ecb_decrypt( src, buffer, (unsigned long) src_len, &ecb );
        if( ret != CRYPT_OK )
            ret = ERR_AES_ERROR;
        else
            ret = ERR_OK;

        if( ret == CRYPT_OK ) { ret = cp_pkcs7_unpad( dst, dst_len, buffer, src_len, mode ); }
        else
        {
            ret = ERR_AES_ERROR;
        }
    }
    free( buffer );

    ecb_done( &ecb );

    /* if( ret == ERR_OK )
    {
        if( mode == MODE_TEXT ) buffer[src_len] = 0;

        *dst     = buffer;
        *dst_len = src_len;
    }*/

    return ret;
}

int
cp_aes_ecb_encrypt( char** dst, size_t* dst_len, const char* src, size_t src_len, const char* key, size_t key_len,
                    int mode )
{
    symmetric_ECB ecb;
    int           cipher, ret;
    char *        buffer = NULL, *encrypted = NULL;

    assert( dst && dst_len );
    assert( src && src_len );
    assert( key && key_len );
    assert( mode == MODE_BINARY || mode == MODE_TEXT );

    if( !dst || !dst_len || !src || !src_len || !key || !key_len || !( mode == MODE_BINARY || mode == MODE_TEXT ) )
    {
        return ERR_INVALID_ARGUMENT;
    }

    cipher = register_cipher( &aes_desc );
    if( cipher == -1 ) return ERR_AES_ERROR;

    ret = ecb_start( cipher, key, (int) key_len, AES_NUM_ROUNDS, &ecb );
    if( ret != CRYPT_OK ) return ERR_AES_ERROR;

    //>ret    = pkcs7_pad( &buffer, &n, src, src_len, AES_BLOCK_SIZE, mode );
    //>if( ret == ERR_OK )
    {
        encrypted = (char*) malloc( src_len + mode );
        if( encrypted )
        {
            ret = ecb_encrypt( src, encrypted, (unsigned long) src_len, &ecb );
            if( ret == CRYPT_OK ) { ret = ERR_OK; }
            else
                ret = ERR_AES_ERROR;
        }
        else
            ret = ERR_INSUFFICIENT_MEMORY;
    }

    ecb_done( &ecb );

    if( ret == ERR_OK )
    {
        *dst     = encrypted;
        *dst_len = src_len;
    }

    free( buffer );

    return ret;
}

int
cp_aes_cbc_encrypt( char** dst, size_t* dst_len, const char* data, size_t data_len, const char* key, size_t key_len,
                    const char* iv, size_t iv_len, int mode )
{
    char*       encrypted = NULL;
    size_t      i, n1 = 0, n2 = 0, n3 = 0, rem = 0, len = 0;
    int         ret;
    const char *s = NULL, *prev = NULL;
    char *      b1 = NULL, *b2 = NULL;

    encrypted = (char*) malloc( data_len + AES_BLOCK_SIZE + mode );
    if( !encrypted ) return ERR_INSUFFICIENT_MEMORY;

    len  = 0;
    prev = iv;
    for( i = 0; i < data_len; i += AES_BLOCK_SIZE )
    {
        s   = data + i;
        rem = i + AES_BLOCK_SIZE < data_len ? AES_BLOCK_SIZE : data_len - i;
        ret = cp_pkcs7_pad( &b1, &n1, s, rem, AES_BLOCK_SIZE, mode );
        ret = cp_repeating_xor( b1, n1, prev, AES_BLOCK_SIZE );
        ret = cp_aes_ecb_encrypt( &b2, &n3, b1, n1, key, key_len, mode );
        memcpy( encrypted + i, b2, n3 );
        len += n3;

        free( b1 );
        free( b2 );

        prev = encrypted + i;
    }

    if( mode == MODE_TEXT ) { encrypted[len] = 0; }

    *dst     = encrypted;
    *dst_len = len;

    return ERR_OK;
}

int
cp_aes_cbc_decrypt( char** dst, size_t* dst_len, const char* data, size_t data_len, const char* key, size_t key_len,
                    const char* iv, size_t iv_len, int mode )
{
    char*       plaintext = NULL;
    size_t      i, n1 = 0, n2 = 0, n3 = 0, rem = 0, len = 0;
    int         ret;
    const char *s = NULL, *prev = NULL;
    char *      b1 = NULL, *b2 = NULL;

    plaintext = (char*) malloc( data_len + mode );
    if( !plaintext ) return ERR_INSUFFICIENT_MEMORY;

    len  = 0;
    prev = iv;
    for( i = 0; i < data_len; i += AES_BLOCK_SIZE )
    {
        s   = data + i;
        ret = cp_aes_ecb_decrypt( &b1, &n1, s, AES_BLOCK_SIZE, key, key_len, mode );
        ret = cp_repeating_xor( b1, n1, prev, AES_BLOCK_SIZE );
        ret = cp_pkcs7_unpad( &b2, &n3, b1, n1, mode );
        memcpy( plaintext + i, b2, n3 );
        len += n3;

        free( b1 );
        free( b2 );

        prev = s;
    }

    if( mode == MODE_TEXT ) { plaintext[len] = 0; }

    *dst     = plaintext;
    *dst_len = len;

    return ERR_OK;
}

int
cp_count_ecb_repetitions( const char* src, size_t src_len, size_t block_size )
{
    int    ret, reps;
    size_t i, j, n_chunks;
    char   key = '\0';

    assert( src_len && src );

    n_chunks = src_len / block_size;
    assert( src_len % block_size == 0 );

    reps = 0;
    for( i = 0; i < n_chunks - 1; i++ )
    {
        for( j = i + 1; j < n_chunks; j++ )
        {
            ret = memcmp( (const char*) src + i * block_size, (const char*) src + j * block_size, block_size );
            if( !ret ) reps += 1;
        }
    }
    return reps;
}

int
cp_repeating_xor( char* dst, size_t dst_len, const char* key, size_t key_len )
{
    assert( dst && dst_len );
    assert( key && key_len );

    if( !dst || !dst_len || !key || !key_len ) { return ERR_INVALID_ARGUMENT; }

    for( size_t i = 0; i < dst_len; i += 1 ) dst[i] ^= key[i % key_len];

    return ERR_OK;
}

int
cp_block_xor( char* dst, const char* src, size_t len )
{
    assert( src && dst && len );
    if( !dst || !src || !len ) { return ERR_INVALID_ARGUMENT; }

    for( size_t i = 0; i < len; i++ ) dst[i] ^= src[i];

    return ERR_OK;
}

int
cp_read_all( char** dst, size_t* dst_len, const char* filename, int mode )
{
    long   file_len;
    int    ret;
    char*  buffer;
    size_t read;

    FILE* fp;

    assert( dst && dst_len );
    assert( filename );
    assert( mode == MODE_BINARY || mode == MODE_TEXT );

    if( !dst || !dst_len || !filename || !( mode == MODE_BINARY || mode == MODE_TEXT ) )
    {
        return ERR_INVALID_ARGUMENT;
    }

    ret = ERR_FILE_ERROR;

    if( fopen_s( &fp, filename, "rb" ) ) { return ret; }

    if( !fseek( fp, 0, SEEK_END ) )
    {
        file_len = ftell( fp );
        if( file_len > 0 && !fseek( fp, 0, SEEK_SET ) )
        {
            buffer = (char*) malloc( file_len + mode );
            if( buffer )
            {
                read = fread( buffer, sizeof( char ), file_len, fp );
                if( read == file_len )
                {
                    if( mode == MODE_TEXT ) { buffer[file_len] = 0; }

                    ret = ERR_OK;

                    *dst     = buffer;
                    *dst_len = file_len;
                }
            }
            else
            {
                ret = ERR_INSUFFICIENT_MEMORY;
            }
        }
    }
    if( ret && buffer ) { free( buffer ); }

    fclose( fp );
    return ret;
}

int
cp_read_lines( const char* filename, cp_line_callback on_line, void* arg )
{
    FILE*  fp;
    char*  line = NULL;
    size_t n;
    int    read, ret, line_idx = 0, len = 0;

    ret = ERR_FILE_ERROR;

    if( fopen_s( &fp, filename, "rb" ) ) { return ret; }

    while( !feof( fp ) )
    {
        read = fgetc( fp );
        if( read == '\n' || read == '\r' ) break;
        len += 1;
    }

    if( !fseek( fp, 0, SEEK_SET ) )
    {
        line = (char*) malloc( len + 3 );    // CR LF + '\0'
        if( line )
        {
            while( fgets( line, len + 3, fp ) != NULL )
            {
                n = strlen( line );
                while( n > 0 && ( line[n - 1] == '\r' || line[n - 1] == '\n' ) ) { line[--n] = '\0'; }

                on_line( line, n, arg, line_idx );

                ++line_idx;
            }
            if( feof( fp ) && !ferror( fp ) ) { ret = ERR_OK; }
        }
        else
        {
            ret = ERR_INSUFFICIENT_MEMORY;
        }
    }
    if( line ) free( line );
    fclose( fp );

    return ret;
}

void
cp_dump_bytes( const char* msg, const char* buf, size_t len )
{
    size_t i;
    printf( "%s\n", msg );
    for( i = 0; i < len; i++ )
        if( isprint( (unsigned char) *( buf + i ) ) )
            printf( "%c", *( buf + i ) );
        else
            printf( "\\x%02x", *( buf + i ) );
    printf( "\n" );
}
