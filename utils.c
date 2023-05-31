#include "utils.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
hex2int( char ch )
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
int2hex( int i )
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
hex2bytes( char** dst, size_t* dst_len, const char* hex_data, size_t hex_len, int mode )
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

    for( i = 0, s = hex_data, p = buffer; i < hex_len; i += 2 ) { *p++ = ( hex2int( *s++ ) << 4 ) | hex2int( *s++ ); }
    if( mode == MODE_TEXT ) { *p = 0; }

    assert( byte_len == p - buffer );
    *dst     = buffer;
    *dst_len = byte_len;

    return ERR_OK;
}

int
bytes2hex( char** dst, size_t* dst_len, const char* byte_data, size_t byte_len, int mode )
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
        *p++ = int2hex( ( *s & 0xF0 ) >> 4 );
        *p++ = int2hex( *s++ & 0x0F );
    }
    if( mode == MODE_TEXT ) { *p = 0; }

    *dst     = buffer;
    *dst_len = hex_len;

    return ERR_OK;
}

int
b64_encode( char** dst, size_t* dst_len, const char* src, size_t src_len, int mode )
{
    size_t      i, n, n_3bytes;
    char *      buffer, *p;
    const char* s;
    int         ch1, ch2, ch3;

    static const char* s_base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    assert( dst && dst_len );
    assert( src && src_len );
    assert( mode == MODE_BINARY || mode == MODE_TEXT );

    if( !dst || !dst_len || !src || !src_len || !( mode == MODE_BINARY || mode == MODE_TEXT ) ) { return ERR_INVALID_ARGUMENT; }

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
b64_decode( char** dst, size_t* dst_len, const char* src, size_t src_len, int mode )
{
    size_t       i, n;
    unsigned int x;
    unsigned     n_sixtets      = 0;
    unsigned     padding        = 0;
    int          spaces_present = 0;
    char *       buffer, *p;

    static const unsigned char s_base64Indices[256] = {
        255, 255, 255, 255, 255, 255, 255, 255, 255, 253, 253, 255, 255, 253, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 253, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 62,  255, 255, 255, 63,
        52,  53,  54,  55,  56,  57,  58,  59,  60,  61,  255, 255, 255, 254, 255, 255, 255, 0,   1,   2,   3,   4,   5,   6,
        7,   8,   9,   10,  11,  12,  13,  14,  15,  16,  17,  18,  19,  20,  21,  22,  23,  24,  25,  255, 255, 255, 255, 255,
        255, 26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,  37,  38,  39,  40,  41,  42,  43,  44,  45,  46,  47,  48,
        49,  50,  51,  255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255 };

    assert( dst && dst_len );
    assert( src && src_len );
    assert( mode == MODE_BINARY || mode == MODE_TEXT );

    if( !dst || !dst_len || !src || !src_len || !( mode == MODE_BINARY || mode == MODE_TEXT ) ) { return ERR_INVALID_ARGUMENT; }

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
break_single_char_xor( char** dst, size_t* dst_len, char* out_key, double* out_score, const char* src, size_t src_len, int mode )
{
    size_t i, j;
    char * buffer, *p;

    double score, max_score;
    char   chosen_key;

    assert( src && src_len );
    assert( mode == MODE_BINARY || mode == MODE_TEXT );

    if( !src || !src_len || !( mode == MODE_BINARY || mode == MODE_TEXT ) ) { return ERR_INVALID_ARGUMENT; }

    buffer = (char*) malloc( src_len + mode );
    if( !buffer ) { return ERR_INSUFFICIENT_MEMORY; }

    max_score = 0.0;
    for( i = 0; i < 256; ++i )
    {
        score = 0.0;
        for( j = 0; j < src_len; ++j ) { score += get_english_letter_score( src[j] ^ (int) i ); }
        if( score > max_score )
        {
            max_score  = score;
            chosen_key = (char) i;
        }
    }
    if( dst && dst_len )
    {
        for( i = 0, p = buffer; i < src_len; ++i ) { *p++ = src[i] ^ chosen_key; }
        if( mode == MODE_TEXT ) { *p = 0; }

        *dst     = buffer;
        *dst_len = src_len;
    }

    if( out_key ) *out_key = chosen_key;
    if( out_score ) *out_score = max_score;

    return ERR_OK;
}

int
apply_repeating_xor( char** dst, size_t* dst_len, const char* src, size_t src_len, const char* key, size_t key_len, int mode )
{
    size_t i;
    int    ch1, ch2;
    char * buffer, *p;

    assert( dst && dst_len );
    assert( src && src_len && key && key_len );
    assert( mode == MODE_BINARY || mode == MODE_TEXT );

    if( !dst || !dst_len || !src || !src_len || !key || !key_len || !( mode == MODE_BINARY || mode == MODE_TEXT ) )
    {
        return ERR_INVALID_ARGUMENT;
    }

    buffer = (char*) malloc( src_len + mode );
    if( !buffer ) { return ERR_INSUFFICIENT_MEMORY; }

    for( i = 0, p = buffer; i < src_len; i += 1 )
    {
        ch1 = src[i];
        ch2 = key[i % key_len];

        *p++ = ch1 ^ ch2;
    }

    if( mode == MODE_TEXT ) { *p = 0; }

    *dst     = buffer;
    *dst_len = src_len;

    return ERR_OK;
}

int
read_all( char** dst, size_t* dst_len, const char* filename, int mode )
{
    long  file_len;
    int   read, ret;
    char* buffer;

    FILE* fp;

    assert( dst && dst_len );
    assert( filename );
    assert( mode == MODE_BINARY || mode == MODE_TEXT );

    if( !dst || !dst_len || !filename || !( mode == MODE_BINARY || mode == MODE_TEXT ) ) { return ERR_INVALID_ARGUMENT; }

    ret = ERR_FILE_ERROR;

    fp = fopen( filename, "rb" );
    if( !fp ) { return ret; }

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
read_lines( const char* filename, line_callback on_line, void* arg )
{
    FILE*  fp;
    char*  line = NULL;
    size_t len, n;
    int    read, ret, line_idx = 0;

    ret = ERR_FILE_ERROR;

    fp = fopen( filename, "rb" );
    if( !fp ) { return ret; }

    len = 0;

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