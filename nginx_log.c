#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <ctype.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <netdb.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/msg.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <mysql/mysql.h>
#include "cjson.h"

typedef enum{
    log,
    wrn,
    err
} log_warn_level;

char log_file[100];
char cfg_file[100];

char db_host[100];
char db_name[100];
char db_user[100];
char db_pass[100];


void sigproc( int sig );
int udp_listen( char* ip, int port );
int load_config();
int mysql_string( char* str, int size );
int write_log( log_warn_level level, const char* fmt, ... );
void get_datetime( int* year, int* month, int* day, int* hour, int* min, int* sec );
int check_ip( char* ip );



int run = 1;
int bufsize;
char ip[16];
char table[50];
int port;

MYSQL* db;
MYSQL_STMT* stmt;
MYSQL_RES* res;
MYSQL_ROW row;

int main( int argc, char* argv[] )
{
    int fd;
    int rc;
    char reff[1024];
    char agent[1024];
    char host[100];
    char uri[1024];
    char buf[10240];
    char sql[10240];
    time_t last;
    
    int year, month, day, hour, min, sec;
    
    struct pollfd pfd;
    struct sockaddr_in addr;
    int len;
    
    cJSON* root;
    cJSON* json_reff;
    cJSON* json_host;
    cJSON* json_uri;
    cJSON* json_agent;
    cJSON* json_status;
    cJSON* json_reqtime;
    cJSON* json_bodysize;
    cJSON* json_addr;
    cJSON* json_method;
    
    if( argc == 1 )
    {
        printf( "usage:nginx_log cfgfile\n" );
        return 1;
    }
    
    strcpy( log_file, "nginx_log.log" );
    snprintf( cfg_file, sizeof(cfg_file), "%s", argv[1] );
    
    write_log( log, "nginx log collecter startup.." );
    

    
    if( load_config() )
    {
        printf( "load config failed!\n" );
        write_log( err, "load config failed!" );
        return 1;
    }
    
    fd = udp_listen( ip, port );
    if( fd == -1 )
    {
        printf( "udp listen failed!\n" );
        write_log( err, "udp listen failed!" );
        return 1;
    }    
    
    
    if( connect_mysql() )
    {
        printf( "connect to mysql failed!\n" );
        write_log( err, "connect to mysql failed!" );
        return 1;
    }
    
    
    signal( SIGINT,  sigproc );
    signal( SIGTERM, sigproc );
    
    last = 0;
    while( run )
    {
        pfd.fd = fd;
        pfd.events = POLLIN;
        
        rc = poll( &pfd, 1, 1000 );
        if( rc <= 0 )
        {
            time_t now = time( NULL );
            if( ( now - last ) > 3600 )
            {
                sprintf( sql, "commit;" );
                mysql_query( db, sql );
                
                last = now;
            }
            
            continue;
        }
        
        len = sizeof( addr );
        memset( buf, 0, sizeof(buf) );
        rc = recvfrom( fd, buf, sizeof(buf), 0, (struct sockaddr *)&addr, &len );
        if( rc <= 0 )
            continue;
        
        root = NULL;
        root = cJSON_Parse( buf );
        if( !root )
        {
            write_log( wrn, "parse json object failed! json:[%s]", buf );
            continue;
        }

        json_addr     = NULL;
        json_host     = NULL;
        json_method   = NULL;
        json_uri      = NULL;
        json_status   = NULL;
        json_reff     = NULL;
        json_agent    = NULL;
        json_reqtime  = NULL;
        json_bodysize = NULL;
        
        
        json_addr     = cJSON_GetObjectItem( root, "ra" );
        json_host     = cJSON_GetObjectItem( root, "tag" );
        json_method   = cJSON_GetObjectItem( root, "me" );
        json_uri      = cJSON_GetObjectItem( root, "uri" );
        json_status   = cJSON_GetObjectItem( root, "st" );
        json_reff     = cJSON_GetObjectItem( root, "ref" );
        json_agent    = cJSON_GetObjectItem( root, "ua" );
        json_reqtime  = cJSON_GetObjectItem( root, "rt" );
        json_bodysize = cJSON_GetObjectItem( root, "bs" );
        
        if( !json_addr || !json_host || !json_method || !json_uri || !json_status || !json_reff || !json_agent || !json_reqtime  || !json_bodysize )
        {
            cJSON_Delete( root );
            continue;
        }
        
        get_datetime( &year, &month, &day, &hour, &min, &sec );
        
        snprintf( reff, sizeof(reff), "%s", json_reff->valuestring );
        snprintf( uri, sizeof(uri), "%s", json_uri->valuestring );
        snprintf( agent, sizeof(agent), "%s", json_agent->valuestring );
        snprintf( host, sizeof(host), "%s", json_host->valuestring );
        
        mysql_string( reff, sizeof(reff) );
        mysql_string( uri, sizeof(uri) );
        mysql_string( agent, sizeof(agent) );
        mysql_string( host, sizeof(host) );
        
        snprintf( sql, sizeof(sql),
        "insert into %s set "
        "access_date = '%d-%02d-%02d', "
        "access_time = '%d-%02d-%02d %02d:%02d:%02d', "
        "host='%s', remote_addr='%s', method='%s', uri='%s', referer='%s', "
        "user_agent='%s', status=%ld, request_time = %f, body_bytes = %ld",
        table,
        year, month, day, 
        year, month, day, hour, min, sec,
        host, json_addr->valuestring, json_method->valuestring, uri, reff,
        agent, json_status->valueint, json_reqtime->valuedouble, json_bodysize->valueint );
        
        cJSON_Delete( root );
        
        //write_log( log, "sql:%s", sql );
        
        if( mysql_query( db, sql ) )
        {
            write_log( err, "insert database failed! err:%s", mysql_error( db ) );
        }
        
        
        
    }
    
    write_log( wrn, "nginx log collector exit!" );
    
    mysql_close( db );
    
    return 0;
    
    
    
}

void sigproc( int sig )
{
    run = 0;
    
}

int connect_mysql()
{
    db = mysql_init( NULL );
    if( !db )
    {
        printf( "mysql_init() failed!\n" );
        return 1;
    }
    
    if( !mysql_real_connect( db, db_host, db_user, db_pass, db_name, 0, NULL, 0 ) )
    {
        printf( "connect to database failed!\n" );
        return 1;
    }
    
    if( mysql_set_character_set( db, "utf8" ) )
    {
        printf( "set charset failed!\n" );
        return 1;
    }
    
    if( mysql_autocommit( db, 1 ) )
    {
        printf( "database set auto commit failed!\n" );
    }
    
    return 0;
    
}

int load_config()
{
    char tmp[100];
    
    if( cfg_get_value( cfg_file, "log", "buf_size", tmp ) )
        return -1;
    bufsize = atoi( tmp );
    
    if( cfg_get_value( cfg_file, "log", "ip", tmp ) )
        return -1;
    
    if( strcmp( tmp, "*" ) )
    {
        if( check_ip( tmp ) )
            return -1;
        
        snprintf( ip, sizeof(ip), "%s", tmp );
    }
    
    if( cfg_get_value( cfg_file, "log", "port", tmp ) )
        return -1;
    port = atoi( tmp );
    
    
    if( cfg_get_value( cfg_file, "db", "db_host", tmp ) )
        return -1;
    snprintf( db_host, sizeof(db_host), "%s", tmp );
    
    if( cfg_get_value( cfg_file, "db", "db_name", tmp ) )
        return -1;
    snprintf( db_name, sizeof(db_name), "%s", tmp );
    
    if( cfg_get_value( cfg_file, "db", "db_user", tmp ) )
        return -1;
    snprintf( db_user, sizeof(db_user), "%s", tmp );
    
    if( cfg_get_value( cfg_file, "db", "db_pass", tmp ) )
        return -1;
    snprintf( db_pass, sizeof(db_pass), "%s", tmp );
    
    if( cfg_get_value( cfg_file, "db", "table", tmp ) )
        return -1;
    snprintf( table, sizeof(table), "%s", tmp );
    
    
    return 0;
}


int write_log( log_warn_level level, const char* fmt, ... )
{
    FILE* f;
    time_t t;
    struct tm* tm;
    va_list  ap;
    //struct timeval tmv;

    f = fopen( log_file, "a" );
    if( f == NULL )
        return -1;
    
    t = time( 0 );
    //gettimeofday( &tmv, NULL );
    
    tm = localtime( &t );
    
    if( *fmt )
    {
        va_start( ap, fmt );
        //fprintf(f,"[%02d-%02d %02d:%02d:%02d.%03d]  ",tm->tm_mon+1,tm->tm_mday,tm->tm_hour,tm->tm_min,tm->tm_sec,tmv.tv_usec / 1000 );
        switch( level )
        {
            case log:
                fprintf( f, "[%02d-%02d %02d:%02d:%02d]  ", tm->tm_mon+1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec );
                break;
            
            case wrn:
                fprintf( f, "[%02d-%02d %02d:%02d:%02d][WRN]  ", tm->tm_mon+1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec );
                break;
            
            default:
                fprintf( f, "[%02d-%02d %02d:%02d:%02d][ERR]  ", tm->tm_mon+1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec );
                break;
        }
        
        vfprintf( f, fmt, ap);
        fprintf( f, "\n" );
        va_end( ap );
    }
    
    fclose( f );
    return 0;
}

int cfg_get_value( const char* file, const char* section, const char* key, char* value )
{
    char line[1024],cursec[1024],tmp[1024];
    char *p;
    FILE* f;

    f=fopen(file,"r");
    if(f==NULL)
        return -1;
    cursec[0]=0;
    
    while( fgets( line, sizeof(line), f ) )
    {
        if( line[0] == '[' ) /* section */
        {
            p = strchr(line,']');
            if( p == NULL)
            {
                continue;    
            }
            p[0] = 0;
            strcpy( cursec, line+1 );
        }
        else if (line[0]=='#') /* commnet */
            continue;
        else
        {
            if( strcmp( section, cursec ) != 0 )
                continue;
            
            while(line[strlen(line)-1]== ' ' || line[strlen(line)-1]== '\t' || line[strlen(line)-1]== '\r' || line[strlen(line)-1]== '\n')
                line[strlen(line)-1]= 0;
                
            while( line[0]==' ' || line[0]=='\t' ) /* 去掉头部的空格 */
            {
                memmove( line, line+1, strlen(line)-1 );
                line[strlen(line)-1]=0;
            }
            
            if( strlen(line) == 0 )
                continue;
            
            strcpy( tmp, line );
            p = strchr( tmp, '=' );
            if( p == NULL )
                continue;
            p[0] = 0;
            
            while( tmp[strlen(tmp)-1] == ' ' || tmp[strlen(tmp)-1] == '\t')
                tmp[strlen(tmp)-1]=0;
            if( strcmp(tmp,key) != 0 )
                continue;
            
            /* 处理值 */
            p = strchr( line, '=' );
            strcpy( tmp, p+1 );
            
            while( tmp[0] == ' ' || tmp[0] == '\t') /* 去掉头部的空格 */
            {
                memmove( tmp, tmp+1, strlen(tmp)-1 );
                tmp[strlen(tmp)-1]=0;
            }
            
            if( tmp[0] == '"' )
            {
                memmove( tmp, tmp+1, strlen(tmp)-1 );
                tmp[strlen(tmp)-1]=0;
            }
            
            if( tmp[strlen(tmp)-1] == '"' )
            {
                    tmp[strlen(tmp)-1]=0;
            }
            /*
            if(strlen(tmp)==0)
            {
                fclose(f);
                return -1;
            }
            */
            strcpy( value, tmp );
            fclose( f );
            return 0;
        }
    }
    
    fclose(f);
    
    return -1;
}

int udp_listen( char* ip, int port )
{
/* ip 表示绑定在哪个ip 上，如果为NULL,表示绑定在所有ip 上，
如果不为null,则绑定在指定ip地址上: 
函数调用成功返回 socket fd, 否则返回 -1  */

    int fd;
    struct sockaddr_in addr;

    fd = socket( AF_INET, SOCK_DGRAM, 0 );
    if( fd == -1 )
    {
        return -1;
    }

    int reuse=1;
    setsockopt( fd, SOL_SOCKET, SO_REUSEADDR, (char*)&reuse, sizeof(reuse) );
    
    addr.sin_family = AF_INET;
    addr.sin_port   = htons( port );

    if(ip == NULL || ip[0] == '*' )
    {
        addr.sin_addr.s_addr = INADDR_ANY;
        if( bind( fd, (struct sockaddr*)&addr, sizeof(addr) ) == -1 )
        {
            close( fd );
            return -1;
        }
    }
    else /*绑定ip  */
    {
        addr.sin_addr.s_addr = inet_addr(ip);
        if( bind( fd, (struct sockaddr*)&addr, sizeof(addr) ) == -1 )
        {
            close( fd );
            return -1;
        }
    }

    return fd;

}

int mysql_string( char* str, int size )
{
    int len = strlen( str );
    int space = size - len-1;
    
    char* p = str;
    
    while( p[0] )
    {
        switch( p[0] )
        {
            case '\'':
            case '\"':
            case '\b':
            case '\r':
            case '\n':
            case '\t':
            case '\\':
                if( space == 0 )
                    return -1;
                
                memmove( p+1, p, strlen( p ) + 1 );
                p[0] = '\\';
                p += 2;
                space --;
                break;
            
            default:
                p++;
        }
    }
    
    
    return 0;
}

void get_datetime( int* year, int* month, int* day, int* hour, int* min, int* sec )
{
    time_t t;
    struct tm* tm;

    t  = time(0);
    tm = localtime(&t);
    *year  = tm->tm_year+1900;
    *month = tm->tm_mon+1;
    *day   = tm->tm_mday;
    *hour  = tm->tm_hour;
    *min   = tm->tm_min;
    *sec   = tm->tm_sec;
}

int check_ip( char* ip )
{
    int len;
    char* p;
    int i;
    int dot_cnt = 0;
    char* dot[3];
    char buf[16];
    int val;
    
    len = strlen( ip );
    
    if( len < 7 || len > 15 )
        return -1;
    
    strcpy( buf, ip );
    
    p = buf;
    for( i = 0; i < len; i++ )
    {
        switch( p[i] )
        {
            case '0':
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
                break;
            
            case '.':
                if( dot_cnt >= 3)
                    return -1;
                dot[dot_cnt] = p+i;
                dot_cnt ++;
                break;
            
            default:
                return -1;
        }
    }

    if( dot_cnt != 3 )
        return -1;
    
    p = buf;
    dot[0][0] = 0;
    len = strlen( p );
    if( len < 1 || len > 3 )
        return -1;
    val = atoi( p );
    if( val < 0 || len > 255 )
        return -1;

    p = dot[0]+1;
    dot[1][0] = 0;
    len = strlen( p );
    if( len < 1 || len > 3 )
        return -1;
    val = atoi( p );
    if( val < 0 || len > 255 )
        return -1;

    p = dot[1]+1;
    dot[2][0] = 0;
    len = strlen( p );
    if( len < 1 || len > 3 )
        return -1;
    val = atoi( p );
    if( val < 0 || len > 255 )
        return -1;

    p = dot[2]+1;
    len = strlen( p );
    if( len < 1 || len > 3 )
        return -1;
    val = atoi( p );
    if( val < 0 || len > 255 )
        return -1;
    
    return 0;
    
}


