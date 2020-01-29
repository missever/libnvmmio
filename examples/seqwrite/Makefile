OBJECTS = main.o
TARGET = seqwrite
CFLAGS = -g
LIBS = -lnvmmio -lpthread -lpmem
LIBPATH = -L../../src
CPPPATH = -I../../src

$(TARGET):$(OBJECTS)
	gcc -o $@ $^ $(CFLAGS) $(LIBS) $(LIBPATH)

.c.o:
	gcc -c $< $(CPPPATH)

clean:
	rm -f $(TARGET) $(OBJECTS)
