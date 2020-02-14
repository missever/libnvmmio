CC = gcc
CFLAGS = -W -Wall -O3
OBJECTS = $(patsubst %.c, %.o, $(wildcard *.c))
TARGET = libnvmmio.a

#CFLAGS += -D_LIBNVMMIO_DEBUG
#CFLAGS += -D_LIBNVMMIO_TIME

all : $(TARGET)

$(TARGET) : $(OBJECTS)
	$(AR) rscv $@ $^

clean:
	$(RM) $(TARGET) $(OBJECTS)
