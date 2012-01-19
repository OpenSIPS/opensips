MENUCONFIG_FILES= cfg.o curses.o items.o commands.o menus.o parser.o main.o
CFLAGS=-g -Wall
LDFLAGS=-lcurses
EXEC_NAME=configure

all: $(MENUCONFIG_FILES)
	$(CC) -o $(EXEC_NAME) $(CFLAGS) $(LDFLAGS) $^

proper:
	rm -f $(EXEC_NAME)
	rm -f $(MENUCONFIG_FILES)
