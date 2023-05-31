#include "utils.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct result
{
    char* decrypted;

    double max_score;
    int    max_line;
    char   max_key;

} result_t;

void
my_line_callback( const char* line, size_t len, void* arg, int line_idx )
{
    int    ret;
    char   key = '\0';
    size_t n1 = 0, n2 = 0;
    char * s1 = NULL, *plaintext = NULL;

    double score;

    result_t* r = (result_t*) arg;

    ret = hex2bytes( &s1, &n1, line, len, MODE_BINARY );
    assert( !ret && s1 && n1 );
    if( ret ) return;

    ret = break_single_char_xor( &plaintext, &n2, &key, &score, s1, n1, MODE_TEXT );
    assert( !ret && plaintext && n2 );
    if( !ret )
    {
        if( score > r->max_score )
        {
            if( r->decrypted ) free( r->decrypted );

            r->decrypted = _strdup( plaintext );

            r->max_score = score;
            r->max_line  = line_idx;
            r->max_key   = key;
        }
    }
    if( s1 ) free( s1 );
    if( plaintext ) free( plaintext );
}

int
main( void )
{
    result_t r;

    memset( &r, 0, sizeof( result_t ) );

    int ret = read_lines( "set1ch4.txt", &my_line_callback, &r );
    if( ret ) return -1;

    printf( "line:      %d\n", r.max_line );
    printf( "key:       %c\n", r.max_key );
    printf( "score:     %.2f\n", r.max_score );
    printf( "decrypted: %s\n", r.decrypted );
    if( r.decrypted ) free( r.decrypted );

    return 0;
}