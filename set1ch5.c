#include "utils.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
main( void )
{
    char * buffer, *hex_buffer;
    size_t n1, n2;

    const char* src_text = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";

    apply_repeating_xor( &buffer, &n1, src_text, strlen( src_text ), "ICE", 3, MODE_BINARY );
    bytes2hex( &hex_buffer, &n2, buffer, n1, MODE_TEXT );
    assert( !strcmp( hex_buffer, "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c6"
                                 "52a3124333a653e2b2027630c692b20283165286326302e27282f" ) );

    printf( "%s\n", hex_buffer );
    free( buffer );
    free( hex_buffer );

    return 0;
}