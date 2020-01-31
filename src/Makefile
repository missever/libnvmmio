OBJECTS = libnvmmio.o radixlog.o uma.o allocator.o rbtree.o debug.o
TARGET = libnvmmio.a
CFLAGS = -lpthread -lpmem -g -D_LIBNVMMIO_DEBUG
#CFLAGS = -lpthread -lpmem -g -D_LIBNVMMIO_TIME
#CFLAGS = -lpthread -lpmem -g

$(TARGET):$(OBJECTS)
	ar rscv $@ $^

.c.o:
	gcc -c $< $(CFLAGS)

clean:
	rm -f $(TARGET) $(OBJECTS)
