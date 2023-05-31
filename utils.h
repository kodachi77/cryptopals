#ifndef UTILS_H__
#define UTILS_H__

int  hex2int( char ch );
char int2hex( int i );

#define ERR_OK                  0
#define ERR_INVALID_ARGUMENT    -1
#define ERR_INSUFFICIENT_BUFFER -2
#define ERR_INSUFFICIENT_MEMORY -3
#define ERR_FILE_ERROR          -4

#define MODE_BINARY 0
#define MODE_TEXT   1

/* 
 * All the functions below allocate buffer large enough for the conversion. 
 * The caller is responsible for freing this buffer. 
 */
int hex2bytes( char** dst, size_t* dst_len, const char* hex_data, size_t hex_len, int mode );
int bytes2hex( char** dst, size_t* dst_len, const char* byte_data, size_t byte_len, int mode );

int b64_encode( char** dst, size_t* dst_len, const char* src, size_t src_len, int mode );
int b64_decode( char** dst, size_t* dst_len, const char* src, size_t src_len, int mode );

int break_single_char_xor( char** dst, size_t* dst_len, char* out_key, double* out_score, const char* src, size_t src_len,
                           int mode );

int apply_repeating_xor( char** dst, size_t* dst_len, const char* src, size_t src_len, const char* key, size_t key_len,
                         int mode );

/* 
 * File utilities. 
 */
int read_all( char** dst, size_t* dst_len, const char* filename, int mode );

typedef void ( *line_callback )( const char* line, size_t len, void* arg, int line_idx );

int read_lines( const char* filename, line_callback on_line, void* arg );

#endif