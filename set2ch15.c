#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"

void
dump_bytes( const char* msg, const char* buf, size_t len )
{
    size_t i;
    printf( msg );
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
    int         i, ret;
    char*       b1               = NULL;
    size_t      n1               = 0;
    const char* padded_strings[] = { "ICE ICE BABY\x04\x04\x04\x04", "ICE ICE BABY\x01\x02\x03\x04",
                                     "ICE ICE BABY\x05\x05\x05\x05" };
    for( i = 0; i < 3; i++ )
    {
        ret = cp_pkcs7_unpad( &b1, &n1, padded_strings[i], strlen( padded_strings[i] ), MODE_TEXT );
        if( ret == ERR_OK ) printf( "padded string: %s\n", b1 );
        if( ret == ERR_INVALID_PADDING )
            dump_bytes( "invalid padding: ", padded_strings[i], strlen( padded_strings[i] ) );
    }

    return 0;
}