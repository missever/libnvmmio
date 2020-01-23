OBJECTS = libnvmmio.o radixlog.o uma.o allocator.o rbtree.o stats.o
TARGET = libnvmmio.a
CFLAGS = -lpthread -lpmem -g

$(TARGET):$(OBJECTS)
	ar rscv $@ $^

.c.o:
	gcc -c $< $(CFLAGS)

clean:
	rm -f $(TARGET) $(OBJECTS)
