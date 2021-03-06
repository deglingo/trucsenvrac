#

PACKAGE = automount
prefix = /usr/local
sbindir = $(prefix)/sbin
sysconfdir = $(prefix)/etc
pkgsysconfdir = $(sysconfdir)/$(PACKAGE)
vardir = /var/local
logdir = $(vardir)/log
udevsysconfdir = /etc/udev/rules.d
cronsysconfdir = /etc/cron.d

# logrotate
logrotatesysconfdir = $(prefix)/etc/logrotate.d
ROTATE_USER = root
ROTATE_GROUP = staff

SHELL = /bin/sh

udev_rules = 10_$(PACKAGE).rules

.PHONY: all install install-admin install-udev install-cron

all: $(udev_rules) automount.stamp-h cron-$(PACKAGE) $(PACKAGE).logrotate

%: %.in conf.sed
	sed -f conf.sed <$< >$@.tmp
	mv -f $@.tmp $@

automount.stamp-h: automount
	$(SHELL) $< -n
	echo >$@

conf.sed: Makefile
	(	echo "s,@PACKAGE@,$(PACKAGE),g"; \
		echo "s,@sbindir@,$(sbindir),g"; \
		echo "s,@pkgsysconfdir@,$(pkgsysconfdir),g"; \
		echo "s,@logdir@,$(logdir),g"; \
		echo "s,@SHELL@,$(SHELL),g"; \
		echo "s,@ROTATE_USER@,$(ROTATE_USER),g"; \
		echo "s,@ROTATE_GROUP@,$(ROTATE_GROUP),g"; \
	) >$@.tmp
	mv -f $@.tmp $@

install:
	test -d "$(sbindir)" || mkdir -p "$(sbindir)"
	install -m755 automount "$(sbindir)"
	test -d "$(pkgsysconfdir)" || mkdir -p "$(pkgsysconfdir)"
	install -m644 example.conf "$(pkgsysconfdir)"
	install -m644 -T $(PACKAGE).logrotate "$(logrotatesysconfdir)/$(PACKAGE)"

install-admin: install-udev install-cron

install-udev:
	install -m664 $(udev_rules) "$(udevsysconfdir)"
	if test -x "`which service`"; then \
		cmd='service udev restart'; \
	elif test -x "`which invoke-rc.d`"; then \
		cmd='invoke-rc.d udev restart'; \
	elif test -x '/etc/init.d/udev'; then \
		cmd='/etc/init.d/udev restart': \
	else \
		echo "E: could not find a daemon starter" >&2; \
		exit 1; \
	fi; \
	echo "$$cmd"; \
	eval "$$cmd" || \
		{ echo "E: could not restart udev" >&2; exit 1; }

install-cron:
	install -m644 cron-$(PACKAGE) "$(cronsysconfdir)"
