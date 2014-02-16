#

PACKAGE = automount
prefix = /usr/local
sbindir = $(prefix)/sbin
sysconfdir = $(prefix)/etc
pkgsysconfdir = $(sysconfdir)/$(PACKAGE)
logdir = /var/local/log
udevsysconfdir = /etc/udev/rules.d

SHELL = /bin/sh

udev_rules = 10_$(PACKAGE).rules

all: $(udev_rules) automount

%.rules: %.rules.in conf.sed
	sed -f conf.sed <$< >$@.tmp
	mv -f $@.tmp $@

automount: automount.in conf.sed
	sed -f conf.sed <$< >$@.tmp
	$(SHELL) $@.tmp -n
	mv -f $@.tmp $@

conf.sed: Makefile
	(	echo "s,@PACKAGE@,$(PACKAGE),g"; \
		echo "s,@sbindir@,$(sbindir),g"; \
		echo "s,@pkgsysconfdir@,$(pkgsysconfdir),g"; \
		echo "s,@logdir@,$(logdir),g"; \
		echo "s,@SHELL@,$(SHELL),g"; \
	) >$@.tmp
	mv -f $@.tmp $@

install:
	test -d "$(sbindir)" || mkdir -p "$(sbindir)"
	install -m755 automount "$(sbindir)"
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
