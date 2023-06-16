#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"

int
main( void )
{
    int         i, ret;
    char*       b1      = NULL;
    size_t      n1      = 0;
    const char* INPUT[] = { "ICE ICE BABY\x04\x04\x04\x04", "ICE ICE BABY\x01\x02\x03\x04",
                            "ICE ICE BABY\x05\x05\x05\x05" };
    for( i = 0; i < ARRAY_SIZE( INPUT ); i++ )
    {
        ret = cp_pkcs7_unpad( &b1, &n1, INPUT[i], strlen( INPUT[i] ), MODE_TEXT );
        if( ret == ERR_OK )
            printf( "padded string: %s\n", b1 );
        else if( ret == ERR_INVALID_PADDING )
            cp_dump_bytes( "invalid padding: ", INPUT[i], strlen( INPUT[i] ) );
        else
            printf( "Unexpected error: %d\n", ret );
    }

    return 0;
}