CROSS_COMPILE ?=mips-linux-uclibc-
CC=$(CROSS_COMPILE)gcc
CFLAGS=-O2

ifeq ($(CROSS_COMPILE),mips-linux-uclibc-)
CFLAGS +=-mips32 -mtune=mips32
endif

OBJS=sum.o md5.o
EXEC=fixsum

all: $(OBJS)
	$(CC) -o $(EXEC) $(OBJS)

clean:
	$(RM) $(OBJS) $(EXEC)
