#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"

typedef struct result
{
    /* caller is responsible for freeing this string */
    char* plaintext;

    double max_score;
    int    max_line;
    char   max_key;

} result_t;

void
my_line_callback( const char* line, size_t len, void* arg, int line_idx )
{
    char * s1 = NULL, *plaintext = NULL;
    char   key = 0;
    size_t n1 = 0, n2 = 0;
    int    ret;

    double score = 0.0;

    result_t* r = (result_t*) arg;

    ret = hex2bytes( &s1, &n1, line, len, MODE_BINARY );
    if( ret != ERR_OK ) return;

    ret = break_single_char_xor( &plaintext, &n2, &key, &score, s1, n1, MODE_TEXT );
    if( ret == ERR_OK )
    {
        if( score > r->max_score )
        {
            if( r->plaintext ) free( r->plaintext );

            r->plaintext = _strdup( plaintext );

            r->max_score = score;
            r->max_line  = line_idx;
            r->max_key   = key;
        }
    }

    free( s1 );
    free( plaintext );
}

int
main( void )
{
    result_t r;

    memset( &r, 0, sizeof( result_t ) );

    int ret = read_lines( "set1ch4.txt", &my_line_callback, &r );
    if( ret != ERR_OK ) return -1;

    printf( "line:      %d\n", r.max_line );
    printf( "key:       %c\n", r.max_key );
    printf( "score:     %.2f\n", r.max_score );
    printf( "decrypted: %s\n", r.plaintext );

    free( r.plaintext );

    return 0;
}