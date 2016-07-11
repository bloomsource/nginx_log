create database nginx default charset utf8;

create user nginx;

grant all on nginx.* to nginx@localhost identified by 'nginx';


flush privileges;


//--------------------------------------------------------


create table nginx_log(
id                int auto_increment primary key,
access_date       date,
access_time       datetime,
host              varchar( 50 ),
remote_addr       varchar( 20 ),
method            varchar( 4  ),
uri               varchar( 1024 ),
referer           varchar( 1024 ),
user_agent        varchar( 1024 ),
status            int,
request_time      decimal( 8, 3 ),
body_bytes        bigint,
index( remote_addr )
);



