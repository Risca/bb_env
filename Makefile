CFLAGS += `pkg-config --cflags gnutls`
LDFLAGS += `pkg-config --libs gnutls`
all: bb_env bb_printenv bb_setenv
bb_env: bb_env.c
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)
bb_printenv bb_setenv:
	ln -sf bb_env $@
