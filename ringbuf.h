#ifndef _RING_BUFF_H_
#define _RING_BUFF_H_
/***********************************************************

ring buffer utility
Develop by Wang Hai Ou.
http://www.bloomsource.org/

any bug or questions , mail to whotnt@126.com

this code is free, you can use it for any purpose.

***********************************************************/

#define ERRCOD_RINGBUF_OK                    0
#define ERRCOD_RINGBUF_NOT_ENOUGH_SPACE      1
#define ERRCOD_RINGBUF_NO_DATA               2
#define ERRCOD_RINGBUF_OUT_OF_RANGE          3





#ifdef __cplusplus
extern "C"{
#endif

typedef struct{
unsigned int bufsize;
unsigned int startpos;
unsigned int datalen;
} ring_buffer_head;



#define ring_buffer_datalen( ringbuf ) ( ((ring_buffer_head*)ringbuf)->datalen )

#define ring_buffer_freespace( ringbuf ) ( ((ring_buffer_head*)ringbuf)->bufsize - ((ring_buffer_head*)ringbuf)->datalen )



/* create a ring buffer memory piece ( dynamic allocate )
size      - size of ring buffer storeage area

return:
    NULL     - malloc failed
    NOT NULL - ring buffer create success,
               use free() to free ringbuffer
*/
extern void* ring_buffer_create( int size );





/* ring buffer init function
ringbuf   - a piece of memory for ring buffer, include ring buffer head
size      - size of ring buffer storeage area

note:
    the total size of memory is size + sizeof(ring_buffer_head)
    void* ringbuf;
    ringbuf = malloc( 1048576 + sizeof(ring_buffer_head) );
    ring_buffer_init( ringbuf, 1048576 );
*/
extern int ring_buffer_init( void* ringbuf, int size );





/* ring buffer read function
ringbuf - pointer to a ringbuf
buf     - buffer to read message
size    - in/out parameter, bring in the size of buf , bring out the 
          size of data actually read

return value:
ERRCOD_RINGBUF_OK               - ok
ERRCOD_RINGBUF_NO_DATA          - no message in the ring buffer          */
extern int ring_buffer_read ( void* ringbuf, char* buf, int* size );





/* ring buffer peek function
ringbuf - pointer to a ringbuf
buf     - buffer to read message
size    - in/out parameter, bring in the size of buf , bring out the 
          size of data actually read

return value:
ERRCOD_RINGBUF_OK               - ok
ERRCOD_RINGBUF_NO_DATA          - no message in the ring buffer          */
extern int ring_buffer_peek( void* ringbuf, char* buf, int* size );





/* ring buffer inc function
ringbuf - pointer to a ringbuf
inc     - how many bytes ring buffer read pointer will increase

return value:
ERRCOD_RINGBUF_OK               - ok
ERRCOD_RINGBUF_OUT_OF_RANGE     - read pointer increase too much

note:
    this function is usefull when after a peek operation,for example,
    you can peek 100 byte data for send, but only send 50 bytes,
    a following ring_buffer_inc call can make ring buffer read postion 
    correct
*/
extern int ring_buffer_inc( void* ringbuf, int inc );





/*  ring buffer write function
ringbuf   - pointer to a ring buffer
buf       - buffer that hold data to write
size      - size of data
return value:
ERRCOD_RINGBUF_OK               - ok
ERRCOD_RINGBUF_NOT_ENOUGH_SPACE - the ring buffer have not engouth space      */
extern int ring_buffer_write( void* ringbuf, char* buf, int size );








#ifdef __cplusplus
}
#endif

#endif


