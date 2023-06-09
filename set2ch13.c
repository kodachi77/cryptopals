#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"

#include <cjson/cJSON.h>

static char*
parse_cookie( char* src, size_t src_len )
{
    char * key = NULL, *value = NULL, *txt = NULL;
    size_t key_len = 0, value_len = 0;

    cJSON* profile = cJSON_CreateObject();
    if( !profile ) { goto end; }

    char* s = src;
    key     = src;
    while( s <= src + src_len )
    {
        if( *s == '=' )
        {
            key_len = s - key;
            *s      = 0;
            ++s;
            value = s;
        }
        else if( *s == '&' || *( s ) == 0 )
        {
            *s = 0;

            char* stopped;
            if( !value )
            {
                /* this should not be happening */
                goto end;
            }

            int num = (int) strtol( value, &stopped, 10 );
            cJSON* value_obj;
            if( *stopped ) { value_obj = cJSON_CreateString( value ); }
            else
            {
                value_obj = cJSON_CreateNumber( num );
            }

            if( value_obj == NULL ) { goto end; }

            cJSON_AddItemToObject( profile, key, value_obj );

            ++s;
            key     = s;
            key_len = 0;
        }

        ++s;
    }
    txt = cJSON_Print( profile );

end:
    cJSON_Delete( profile );
    return txt;
}

static int
blackbox_encrypt_internal( char** dst, size_t* dst_len, const char* src, size_t src_len, const char* key,
                           size_t key_len )
{
    if( !dst || !dst_len || !src || !src_len || !key || !key_len ) return ERR_INVALID_ARGUMENT;

    size_t len    = src_len + AES_BLOCK_SIZE;
    char* buffer = (char*) malloc( len );
    if( !buffer ) return ERR_INSUFFICIENT_MEMORY;

    static const char IV[AES_BLOCK_SIZE] = { 0 };

    size_t padded_len;
    int ret = cp_pkcs7_pad( &buffer, &padded_len, src, src_len, AES_BLOCK_SIZE, MODE_BINARY );
    if( ret != ERR_OK ) { return ret; }

    ret = cp_aes_ecb_encrypt( dst, dst_len, buffer, padded_len, key, key_len, MODE_BINARY );
    free( buffer );

    return ret;
}

static char unknown_key[AES_BLOCK_SIZE];

static int
profile_for( char** dst, size_t* dst_len, const char* email, size_t email_len )
{
    static const char* s_prefix    = "email=";
    static const char* s_postfix   = "&uid=10&role=user";
    size_t             prefix_len  = strlen( s_prefix );
    size_t             postfix_len = strlen( s_postfix );
    size_t             n1          = email_len + prefix_len + postfix_len;
    size_t             i;

    char* b1 = (char*) malloc( n1 );
    if( !b1 ) return ERR_INSUFFICIENT_MEMORY;

    memcpy( b1, s_prefix, prefix_len );
    memcpy( b1 + prefix_len, email, email_len );
    memcpy( b1 + prefix_len + email_len, s_postfix, postfix_len );

    for( i = 0; i < email_len; i++ )
    {
        if( email[i] == '=' || email[i] == '&' ) b1[prefix_len + i] = '%';
    }

    return blackbox_encrypt_internal( dst, dst_len, b1, n1, unknown_key, AES_BLOCK_SIZE );
}

static int
blackbox_decrypt( char** dst, const char* src, size_t src_len )
{
    char*  buffer = NULL;
    size_t len;
    int ret    = cp_aes_ecb_decrypt( &buffer, &len, src, src_len, unknown_key, AES_BLOCK_SIZE, MODE_TEXT );
    assert( ret == ERR_OK && buffer && len );
    char* cookie = parse_cookie( buffer, len );
    assert( cookie );

    if(dst)
        *dst = cookie;

    free( buffer );
    
    return cookie != NULL ? ERR_OK : ERR_GENERIC_ERROR;
}

int
main( void )
{
    int ret = cp_generate_random_string( unknown_key, AES_BLOCK_SIZE, AES_BLOCK_SIZE );
    assert( ret == ERR_OK );

    /* In this particular exercise we are not going to determine block size and ensure that this is ECB encryption.
     * We already know how to do that.
     * 
     * First we make email long enough to make the word 'admin' to be block aligned admin should have a valid 
     * padding till the end of the block.
     * 
     * Second email must be long enough to align text up to user's role with 3rd block boundary.
     * 
     * | BLOCK 1          | BLOCK 2          | BLOCK 3          | BLOCK 4
     * | ................ | ................ | ................ | .
     * | email=zzzzzzzzzz | admin----------- | &uid=10&role=use | r
     * | email=foo11@bar. | com&uid=10&role= | admin............|
     */

    size_t key1_len    = strlen( "zzzzzzzzzzadmin" );
    size_t postfix_len = AES_BLOCK_SIZE - strlen( "admin" );

    char * encrypted1 = NULL, *encrypted2 = NULL;
    size_t len1, len2;

    char email1[2 * AES_BLOCK_SIZE] = { 0 };
    char email2[AES_BLOCK_SIZE]     = { 0 };

    char compromised_cypher[3 * AES_BLOCK_SIZE] = { 0 };

    memcpy( email1, "zzzzzzzzzzadmin", key1_len );
    memset( email1 + key1_len, (char) postfix_len, postfix_len );
    ret = profile_for( &encrypted1, &len1, email1, 2 * AES_BLOCK_SIZE );
    assert( ret == ERR_OK && encrypted1 && len1 == 4 * AES_BLOCK_SIZE );

    memcpy( email2, "foo11@bar.com", strlen( "foo11@bar.com" ) );
    assert( strlen( "email=foo11@bar.com&uid=10&role=" ) == 2 * AES_BLOCK_SIZE );
    
    ret = profile_for( &encrypted2, &len2, email2, strlen( "foo11@bar.com" ) );
    assert( ret == ERR_OK && encrypted2 && len2 == 3 * AES_BLOCK_SIZE );

    memcpy( compromised_cypher, encrypted2, 2 * AES_BLOCK_SIZE );
    memcpy( compromised_cypher + 2 * AES_BLOCK_SIZE, encrypted1 + AES_BLOCK_SIZE, AES_BLOCK_SIZE );

    char* buffer = NULL;
    ret = blackbox_decrypt( &buffer, compromised_cypher, 3 * AES_BLOCK_SIZE );
    assert( ret == ERR_OK );

    printf( "Decrypted string:\n%s\n", buffer );

    free( buffer );
    free( encrypted1 );
    free( encrypted2 );

    return 0;
}