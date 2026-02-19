CC = gcc
CFLAGS = -Wall -Wextra -MMD -MP

SRCDIR = src
BINDIR = bin

SRCS = tui.c proto.c sync.c sha256.c aes.c
OBJS = $(SRCS:%.c=$(BINDIR)/%.o)
DEPS = $(OBJS:.o=.d)

$(BINDIR)/dcomms: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) -lpthread

$(BINDIR)/%.o: $(SRCDIR)/%.c | $(BINDIR)
	$(CC) $(CFLAGS) -I$(SRCDIR) -c $< -o $@

$(BINDIR):
	mkdir -p $(BINDIR)

clean:
	rm -rf $(BINDIR) messages.db
	rm -rf chats/

-include $(DEPS)

.PHONY: clean
