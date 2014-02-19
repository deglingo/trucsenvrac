#

prefix = /usr/local
sbindir = $(prefix)/sbin
cronsysconfdir = /etc/cron.d

.PHONY: all install install-admin install-cron

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

install-admin: install-cron

install-cron:
	install -m644 "cron-nfswatch" "$(cronsysconfdir)"
