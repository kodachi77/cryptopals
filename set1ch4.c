#include "utils.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct result
{
    /* caller is responsible for freeing this string */
    char* plaintext;

    double score;
    int    line;
    char   key;

} result_t;

void
my_line_callback( const char* line, size_t len, void* arg, int line_idx )
{
    result_t* r = (result_t*) arg;

    char*  b1  = NULL;
    size_t n1  = 0;
    int    ret = cp_hex2bytes( &b1, &n1, line, len, MODE_TEXT );
    if( ret != ERR_OK ) return;

    char   key   = 0;
    double score = 0.0;
    ret          = cp_break_single_char_xor( b1, n1, &key, &score );
    if( ret == ERR_OK )
    {
        if( score > r->score )
        {
            if( r->plaintext ) free( r->plaintext );

            r->plaintext = strdup( b1 );

            r->score = score;
            r->line  = line_idx;
            r->key   = key;
        }
    }

    free( b1 );
}

int
main( void )
{
    result_t r;
    memset( &r, 0, sizeof( result_t ) );

    int ret = cp_read_lines( "set1ch4.txt", &my_line_callback, &r );
    assert( ret == ERR_OK );

    printf( "line:      %d\n", r.line );
    printf( "key:       '%c'\n", r.key );
    printf( "score:     %.2f\n", r.score );
    printf( "decrypted: %s\n", r.plaintext );

    free( r.plaintext );

    return 0;
}