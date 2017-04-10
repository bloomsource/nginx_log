
nginx_log:nginx_log.o ringbuf.o cjson.o rbtree.o
	gcc -o $@ $^  -lmysqlclient -L/usr/lib64/mysql/ -lm

clean:
	rm -f *.o
c:clean

