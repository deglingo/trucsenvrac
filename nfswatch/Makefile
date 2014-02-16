#

prefix = /usr/local
sbindir = $(prefix)/sbin
cronsysconfdir = /etc/cron.d

all: nfswatch cron-nfswatch

%: %.in conf.sed
	sed -f conf.sed <$< >$@.tmp
	mv -f $@.tmp $@

conf.sed: Makefile
	(	echo "s,@sbindir@,$(sbindir),g"; \
	) >$@.tmp
	mv -f $@.tmp $@

install: all
	test -d "$(sbindir)" || mkdir -p "$(sbindir)"
	install -m755 nfswatch "$(sbindir)"
	test -d "$(cronsysconfdir)" || mkdir -p "$(cronsysconfdir)"
	install -m644 "cron-nfswatch" "$(cronsysconfdir)"
