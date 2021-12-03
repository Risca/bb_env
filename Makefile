all: bb_env bb_printenv bb_setenv
bb_env: bb_env.c
bb_printenv bb_setenv:
	ln -sf bb_env $@
