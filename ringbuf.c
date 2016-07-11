#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ringbuf.h"


static int _pos_add( int bufsize, int pos , int add );

static int _read_from_pos( void* ringbuf, int buflen, int pos ,
                           void* buf, int size );
static int _write_from_pos( void* ringbuf, int buflen, int pos ,
                            void* buf, int size );

void* ring_buffer_create( int size )
{
    void* p;
    p = malloc( size + sizeof(ring_buffer_head) );
    if( p == NULL )
        return NULL;
    
    ring_buffer_init( p, size );
    return p;
    
    
}


int ring_buffer_init( void* ringbuf, int size )
{
    ring_buffer_head* head;
    head = (ring_buffer_head*)ringbuf;
    
    head->bufsize  = size;
    head->startpos = 0;
    head->datalen  = 0;
    
    return 0;
}

int ring_buffer_read( void* ringbuf, char* buf, int* size )
{
    ring_buffer_head* head = (ring_buffer_head*)ringbuf;
    void* data = ringbuf + sizeof(ring_buffer_head);
 
    int readlen;
    
    if( head->datalen == 0 ) /* no data */
        return ERRCOD_RINGBUF_NO_DATA;

    
    readlen = *size;
    
    if( readlen > head->datalen )
        readlen = head->datalen;
    
    *size = readlen;
    _read_from_pos( data, head->bufsize, head->startpos, buf, readlen );
    
    head->startpos = _pos_add( head->bufsize, head->startpos, readlen );
    head->datalen -= readlen;
    return 0;
}

int ring_buffer_inc( void* ringbuf, int inc )
{
    ring_buffer_head* head = (ring_buffer_head*)ringbuf;
    
    if( inc > head->datalen )
        return ERRCOD_RINGBUF_OUT_OF_RANGE;
    
    head->datalen -= inc;
    head->startpos = _pos_add( head->bufsize, head->startpos, inc );
    
    return 0;
}


int ring_buffer_peek( void* ringbuf, char* buf, int* size )
{
    ring_buffer_head* head = (ring_buffer_head*)ringbuf;
    void* data = ringbuf + sizeof(ring_buffer_head);
 
    int readlen;
    
    if( head->datalen == 0 ) /* no data */
        return ERRCOD_RINGBUF_NO_DATA;

    
    readlen = *size;
    
    if( readlen > head->datalen )
        readlen = head->datalen;
    
    *size = readlen;
    _read_from_pos( data, head->bufsize, head->startpos, buf, readlen );
    
    return 0;
}

int ring_buffer_write( void* ringbuf, char* buf, int size )
{
    ring_buffer_head* head = (ring_buffer_head*)ringbuf;
    void* data = ringbuf + sizeof(ring_buffer_head);
    int pos;
    
    pos = head->startpos + head->datalen;
    
    if( size > ( head->bufsize - head->datalen ) )
        return ERRCOD_RINGBUF_NOT_ENOUGH_SPACE;
    
    pos = head->startpos + head->datalen;
    if( pos >= head->bufsize )
        pos -= head->bufsize;

    _write_from_pos( data, head->bufsize, pos, buf, size );
    
    head->datalen += size;
    
    return 0;
}

static int _read_from_pos( void* ringbuf, int buflen, int pos ,
                           void* buf, int size )
{
    int readable_len;
    int readlen;
    int left;
    
    readable_len = buflen - pos;
    
    left = size;
    readlen = left > readable_len ? readable_len : left;
    
    memcpy( buf, ringbuf + pos, readlen );
    
    left -= readlen;
    if( left )
        memcpy( buf + readlen, ringbuf, left );
        
    return 0;
    
}

static int _pos_add( int bufsize, int pos , int add )
{
    pos += add;
    if( pos >= bufsize )
        pos -= bufsize;
    
    return pos;

}

static int _write_from_pos( void* ringbuf, int buflen, int pos ,
                            void* buf, int size )
{
    int readable_len;
    int readlen;
    int left;
    
    readable_len = buflen - pos;
    
    left = size;
    readlen = left > readable_len ? readable_len : left;
    
    memcpy( ringbuf + pos, buf, readlen );
    
    left -= readlen;
    if( left )
        memcpy( ringbuf, buf + readlen, left );
        
    return 0;

}




