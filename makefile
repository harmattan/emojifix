EDITION := harmattan
#EDITION := fremantle

all: libsms-utils.so.0

libsms-utils.so.0: libsms-utils.so.0.0.0
	ln -s $< $@

libsms-utils.so.0.0.0: src/libxconv.c libemojitils.so
	$(CC) $(CFLAGS) -fPIC -shared -Wl,--no-as-needed -L. -lemojitils -o $@ $< -ldl
	chmod -x $@

libemojitils.so: libemojitils.so.0
	ln -s $< $@

libemojitils.so.0: original/libsms-utils.so.0.0.0.$(EDITION) patcher
	rm -f $@
	./patcher $< $@

patcher: src/patcher.c
	$(CC) -o $@ $<

clean:
	rm -f patcher libemojitils.so.0 libemojitils.so libsms-utils.so.0.0.0 libsms-utils.so.0

.PHONY: all clean
