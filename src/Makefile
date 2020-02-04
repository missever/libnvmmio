CC = gcc
CFLAGS = -W -Wall -g
OBJECTS = $(patsubst %.c, %.o, $(wildcard *.c))
TARGET = libnvmmio.a

#CFLAGS += -D_LIBNVMMIO_DEBUG
#CFLAGS += -D_LIBNVMMIO_TIME

all : $(TARGET)

$(TARGET) : $(OBJECTS)
	$(AR) rscv $@ $^

clean:
	$(RM) $(TARGET) $(OBJECTS)
