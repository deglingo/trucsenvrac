#

prefix = /usr/local
bindir = $(prefix)/bin

all:

install:
	test -d "$(bindir)" || mkdir "$(bindir)"
	install -m 755 -T passtool.py "$(bindir)/passtool"
