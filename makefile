
nginx_log:nginx_log.o ringbuf.o cjson.o
	gcc -o $@ $^  -lmysqlclient -L/usr/lib64/mysql/

clean:
	rm -f *.o
c:clean

