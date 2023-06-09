#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "utils.h"

void
dump_bytes( const char* buf, size_t len )
{
    size_t i;
    for( i = 0; i < len; i++ )
        if( isprint( *( buf + i ) ) )
            printf( "%c", *( buf + i ) );
        else
            printf( "\\x%02x", *( buf + i ) );
    printf( "\n" );
}

int
main( void )
{
    char * buffer1 = NULL, *buffer2 = NULL;
    size_t len1 = 0, len2 = 0;
    int    ret;

    static const char* BLOCK = "YELLOW SUBMARINE";
    ret                      = pkcs7_pad( &buffer1, &len1, BLOCK, strlen( BLOCK ), 20, MODE_BINARY );
    assert( ret == ERR_OK && buffer1 && len1 );

    ret = pkcs7_unpad( &buffer2, &len2, buffer1, len1, MODE_TEXT );
    assert( ret == ERR_OK && buffer2 && len2 );

    assert( len2 == strlen( BLOCK ) );
    assert( !strcmp( buffer2, BLOCK ) );

    dump_bytes( buffer1, len1 );

    return 0;
}
