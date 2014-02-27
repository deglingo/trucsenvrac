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
CRON_RULE = '*/5 * * * *'

# logrotate
logrotatesysconfdir = $(sysconfdir)/logrotate.d
ROTATE_USER = $(CRON_USER)
ROTATE_GROUP = staff

.PHONY: all install install-admin install-cron install-logrotate

all: $(PACKAGE) myip-update-hosts cron-$(PACKAGE) $(PACKAGE)-rotate

%: %.in conf.sed
	sed -f conf.sed <$< >$@.tmp
	mv -f $@.tmp $@

conf.sed: Makefile
	test `id -u` -ne 0 || { \
		echo "E: won't update conf.sed as root - run make as non-root user first" >&2; \
		exit 1; }
	(	echo "s,@PACKAGE@,$(PACKAGE),g;"; \
		echo "s,@bindir@,$(bindir),g;"; \
		echo "s,@sysconfdir@,$(sysconfdir),g;"; \
		echo "s,@pkgvardir@,$(pkgvardir),g;"; \
		echo "s,@logdir@,$(logdir),g;"; \
		echo "s,@CRON_USER@,$(CRON_USER),g;"; \
		echo "s,@CRON_RULE@,`echo $(CRON_RULE)`,g;"; \
		echo "s,@ROTATE_USER@,$(ROTATE_USER),g;"; \
		echo "s,@ROTATE_GROUP@,$(ROTATE_GROUP),g;"; \
	) >$@.tmp
	mv -f $@.tmp $@

install: all
	test -d "$(bindir)" || mkdir -p "$(bindir)"
	test -d "$(pkgvardir)" || mkdir -m2775 -p "$(pkgvardir)"
	test -d "$(logdir)" || mkdir -m2775 -p "$(logdir)"
	install -m755 $(PACKAGE) "$(bindir)"
	install -m755 myip-update-hosts "$(bindir)"
	install -m644 -T $(PACKAGE)-rotate "$(logrotatesysconfdir)/$(PACKAGE)"

install-admin: install-cron

install-cron:
	install -m644 cron-$(PACKAGE) "$(cronsysconfdir)"
