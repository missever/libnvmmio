CC = gcc
OBJECTS = $(patsubst %.c, %.o, $(wildcard *.c))
TARGET = seqwrite
LIBS = -lnvmmio -lpthread -lpmem
LIBPATH = -L../../src
INCLUDE = -I../../src
CFLAGS = -g $(INCLUDE)

$(TARGET):$(OBJECTS)
	gcc -o $@ $^ $(CFLAGS) $(LIBS) $(LIBPATH)

clean:
	rm -f $(TARGET) $(OBJECTS)
