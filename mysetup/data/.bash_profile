#

echo "## `id -un`:`id -gn`"
TTY="`tty 2>&1`" \
	&& { ISATTY=1; echo "## $TTY"; } \
	|| { ISATTY=0; echo "## <notty>"; }

export PATH="$HOME/local/bin:$PATH"
export PKG_CONFIG_PATH="$HOME/local/lib/pkgconfig"
export LBDIR="$HOME/lb"
export WINEPREFIX="$HOME/.wine"
export PYTHONPATH="/usr/local/lib/python3.2/site-packages:$HOME/local/lib/python3.2/site-packages"
export ACLOCAL_PATH="$HOME/local/share/aclocal"

# [temp]
export GMB_CONFIGDIR='/home/cedric/.gmb'
export GMB_SRCDIR='/src'
export GMB_BUILDDIR='/build'
export TMPDIR='/tmp'

# echo "PATH=$PATH"
# echo "PKG_CONFIG_PATH=$PKG_CONFIG_PATH"
# echo "##"

# keychain
if test $ISATTY -ne 0; then
	if test -x "`which keychain`"; then
		keychain id_rsa
		[ -z "$HOSTNAME" ] && HOSTNAME="`uname -n`"
		[ -f $HOME/.keychain/$HOSTNAME-sh ] \
			&& . $HOME/.keychain/$HOSTNAME-sh
        [ -f $HOME/.keychain/$HOSTNAME-sh-gpg ] \
            && . $HOME/.keychain/$HOSTNAME-sh-gpg
	else
		echo
		echo " * keychain not installed!"
		echo
	fi
fi
