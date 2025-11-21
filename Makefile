CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99
TARGET = feal_ready
FEAL_TARGET = feal
SOURCES = attack.c cipher.c data.c
OBJECTS = $(SOURCES:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJECTS)

$(FEAL_TARGET): feal.c
	$(CC) $(CFLAGS) -o $(FEAL_TARGET) feal.c

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET) $(FEAL_TARGET)

test: $(TARGET)
	./$(TARGET) known.txt

.PHONY: all clean test

