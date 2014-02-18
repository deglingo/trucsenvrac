#

PACKAGE = myip
prefix = /usr/local
bindir = $(prefix)/bin
sysconfdir = $(prefix)/etc
vardir = /var/local
pkgvardir = $(vardir)/$(PACKAGE)
logdir = $(vardir)/log

# cron
cronsysconfdir = /etc/cron.d
CRON_USER = `id -un`

# logrotate
logrotatesysconfdir = /etc/logrotate.d
ROTATE_USER = $(CRON_USER)
ROTATE_GROUP = staff

.PHONY: all install install-admin install-cron install-logrotate

all: $(PACKAGE) cron-$(PACKAGE) $(PACKAGE)-rotate

%: %.in conf.sed
	sed -f conf.sed <$< >$@.tmp
	mv -f $@.tmp $@

conf.sed: Makefile
	(	echo "s,@PACKAGE@,$(PACKAGE),g;"; \
		echo "s,@bindir@,$(bindir),g;"; \
		echo "s,@sysconfdir@,$(sysconfdir),g;"; \
		echo "s,@pkgvardir@,$(pkgvardir),g;"; \
		echo "s,@logdir@,$(logdir),g;"; \
		echo "s,@CRON_USER@,$(CRON_USER),g;"; \
		echo "s,@ROTATE_USER@,$(ROTATE_USER),g;"; \
		echo "s,@ROTATE_GROUP@,$(ROTATE_GROUP),g;"; \
	) >$@.tmp
	mv -f $@.tmp $@

install: all
	test -d "$(bindir)" || mkdir -p "$(bindir)"
	test -d "$(pkgvardir)" || mkdir -m2775 -p "$(pkgvardir)"
	test -d "$(logdir)" || mkdir -m2775 -p "$(logdir)"
	install -m755 $(PACKAGE) "$(bindir)"

install-admin: install-cron install-logrotate

install-cron:
	install -m644 cron-$(PACKAGE) "$(cronsysconfdir)"

install-logrotate:
	install -m644 -T $(PACKAGE)-rotate "$(logrotatesysconfdir)/$(PACKAGE)"
