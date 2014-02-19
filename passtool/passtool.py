#!/usr/bin/python3

import sys, os, getopt, getpass, subprocess, re
import traceback, gzip, functools, glob, time
import collections, types, configparser
import hashlib as _hashlib


# USAGE:
#
USAGE = """\
USAGE: passtool [-G|-P] [OPTIONS] [NAME...]  -- generate passwords/passphrases
       passtool -W [OPTIONS] [SOURCE...]     -- generate a words list

OPTIONS:

  -G, --gen-passwords    generate passwords
  -P, --gen-passphrases  generate passphrases by default
  -W, --gen-wordlist     generate a words list

  -r, --rand             use /dev/random as rand source (no key)
  -R, --urand            use /dev/urandam as rand source (no key)
  -k, --key              use a private key to generate reproducible
                         passwords (default)
  -K, --private-key KEY  give the private key on command line
  -f, --file FILE        read names from file
  -s, --salt SALT        add some salt for this run only
                         (does _not_ override other ones)
  -g                     debug
"""


# str2bool:
#
def str2bool(s) :
    return STR2BOOL[s.lower()]

STR2BOOL = types.MappingProxyType(dict(
    [(s, True) for s in ('true', 't', 'yes', 'y', '1')] + \
    [(s, False) for s in ('false', 'f', 'no', 'n', '0')]))


# sha512bits:
#
# Get an sha512 sum as a 512 bits integer.
#
def sha512bits (string, *salts) :
    h = _hashlib.sha512(string.encode()) # [fixme] encode
    for s in salts :
        h.update(b'\x00')
        h.update(s.encode())
    b = int(h.hexdigest(), 16)
    # trace("SHA512: '%s' + %s\n  %064x\n  %064x" %
    #       (string, salts, b >> 256, b & ((1 << 256) - 1)))
    return int(h.hexdigest(), 16)
        

# Debug
ENABLE_DEBUG = False
LOG_LOCATIONS = str2bool(os.environ.get('PASSTOOL_LOG_LOCATIONS', 'n'))

# change this if you want
SYSTEM_SALT = 'passtool-system-salt'

# extracts 'acceptable' words from a string
RE_WORD = re.compile(r"(^|[^a-z])([a-z]{4,8})($|[^a-z])",
                     re.IGNORECASE)

RE_CFGLINE = re.compile("""
 (?P<EMPTY>^\s*$)
|(?P<COMMENT>\s*[#;%].*$)
#|(?P<SECTION>\s*\[\s*(?P<TITLE>.*\S)\s*\]\s*$)
|(?P<PARAM>\s*(?P<NAME>[a-z_]+)\s*=\s*(?P<VALUE>(.*\S|))\s*$)
""", re.VERBOSE)


RE_NAMESPEC = re.compile(r"""
\s*((\{(?P<OPTS>([^\}\#\\]|\\.)*)\})|)
\s*((?P<ID>[^/\# \t\n]+)|)
\s*((/(?P<SALT>[^/\# \t\n]*))|)
\s*((/\s*(?P<NAME>[^/\#]*[^/\# \t\n]))|)
\s*((?P<COM>\#.*)|)
\s*
""", re.VERBOSE)

RE_NSPECOPT = re.compile(r"""
\s*
(?P<NOT>\!|)
(?P<NAME>(\*)|(\++)|([a-z_\*]+))\s*
((=\s*(?P<VALUE>([^/\\]|\\.)*))|)
(/|$)
""", re.VERBOSE)


# Character classes:
#
CLASSES = {
    'up': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    'lw': 'abcdefghijklmnopqrstuvwxyz',
    'dg': '0123456789',
    'op': ',;:!?./%*$&"#\'-_@=+()[]{}<>',
    'ws': '013456789$%#*@/:;,!?',
}


# log funcs:
#
def _log (f, lvl, msg, depth=0) :
    if LOG_LOCATIONS :
        fn, ln, fc, co = traceback.extract_stack()[-(depth+2)]
        loc = '%s:%d:%s:' % (fn, ln, fc)
    else :
        loc = ''
    f.write('passtool:%s%s%s %s\n' %
            (loc, lvl, (':' if lvl else ''), msg))

def trace (msg, depth=0) :
    if ENABLE_DEBUG : _log(sys.stdout, 'DEBUG', msg, depth=depth+1)
def info (msg, depth=0) : _log(sys.stdout, '', msg, depth=depth+1)
def warn (msg, depth=0) : _log(sys.stderr, 'WARNING', msg, depth=depth+1)
def error (msg, depth=0) : _log(sys.stderr, 'ERROR', msg, depth=depth+1)
def die (msg, depth=0) : error(msg, depth=depth+1); sys.exit(1)



# format_exception:
#
def format_exception (exc_info=None) :
    tp, exc, tb = \
      sys.exc_info() if exc_info is None \
      else exc_info
    lines = [('%s:%d:%s:' % (fn, ln, fc), co)
             for fn, ln, fc, co in traceback.extract_tb(tb)]
    cw = [max(len(l[c]) for l in lines) for c in range(2)]
    msg = '%s: %s\n' % (tp.__name__, exc)
    if len(msg) > 200 : msg = msg[:197] + '...'
    sep1 = ('=' * max(len(msg) - 1, (sum(cw) + 4))) + '\n'
    sep2 = ('-' * max(len(msg) - 1, (sum(cw) + 4))) + '\n'
    plines = [sep1, msg, sep2]
    plines.extend('%s%s -- %s\n' %
                  (l[0], (' ' * (cw[0] - len(l[0]))), l[1])
                  for l in reversed(lines))
    plines.append(sep1)
    return plines


# print_exception:
#
def print_exception (exc_info=None, f=None) :
    if f is None : f = sys.stderr
    f.writelines(format_exception(exc_info))


# get_nbits:
#
def get_nbits (n) :
    b = 0
    while n :
        n >>= 1
        b += 1
    return b


# file_type:
#
def file_type (fname) :
    try:
        tp = subprocess.check_output(['file', '-L', '--mime', '--brief', fname],
                                     universal_newlines=True).split(';')[0]
    except:
        raise
    return tp


# Config:
#
class Config :


    # __init__:
    #
    def __init__ (self) :
        self.usrcfgdir = os.path.join(os.environ['HOME'], '.passtool')
        self.wordlist = os.path.join(self.usrcfgdir, 'wordlist.gz')
        self.input_files = ''
        self.extra_passes = '0'
        self.rand_source = 'key'
        self.private_key = ''
        self.passphrases = False
        self.sys_salt = 'SYSTEM_SALT'
        self.usr_salt = ''
        self.cmd_salt = ''
        self.case_type = 'cap' # cap | low | up | rand | mix


    # get_int:
    #
    def get_int (self, name) :
        return int(getattr(self, name))


    # get_vstr:
    #
    def get_vstr (self, name, sep=None, empty=False) :
        v = [w.strip() for w in getattr(self, name).split(sep)]
        if empty : return v
        else : return [w for w in v if w]

        
    # read_file_list:
    #
    def read_file_list (self, flist) :
        for fname in flist :
            if os.path.exists(fname) :
                trace("reading config file '%s'" % fname)
                self.read_file(open(fname), fname)
            else :
                trace("file '%s' does not exist" % fname)

            
    # read_file:
    #
    def read_file (self, f, fname) :
        match = RE_CFGLINE.match
        lno = 0
        for line in f :
            lno += 1
            m = match(line)
            if m is None : die("%s:%d: invalid line: %s" % (fname, lno, line.strip()))
            if m.lastgroup in ('EMPTY', 'COMMENT') :
                continue
            elif m.lastgroup == 'PARAM' :
                name, value = m.group('NAME', 'VALUE')
                trace(" - '%s' = '%s'" % (name, value))
                setattr(self, name, value)
                #trace("param: '%s' = '%s'" % (name, value))
            else :
                assert 0, m.lastgroup

        
# WordSourceFile:
#
class WordSourceFile :


    # __init__:
    #
    def __init__ (self, fname) :
        self.__fname = fname
        self.__ftype = file_type(fname)


    # __repr__:
    #
    def __repr__ (self) :
        return '<file: %s (%s)>' % (self.__fname, self.__ftype)


    # __iter__:
    #
    def __iter__ (self) :
        if self.__ftype == 'application/gzip' :
            f = gzip.open(self.__fname, 'rb')
        else :
            error("unhandled file type: %s (%s)" %
                  (self.__fname, self.__ftype))
            return
        for bline in f :
            # [fixme] use some codec
            yield ''.join(chr(c) for c in bline)
        f.close()


# WordList:
#
class WordList (object) :


    nwords = property(lambda self: len(self.__words))
    nforbidden = property(lambda self: len(self.__blacklist))
    nusable = property(lambda self: len(set(self.__words).difference(self.__blacklist)))

    
    # __init__:
    #
    def __init__ (self) :
        self.__words = ()
        self.__blacklist = set()


    # read_file:
    #
    def read_file (self, fname, blacklist=False) :
        if not os.path.exists(fname) :
            info("NOTE: file '%s' does not exist" % fname)
            return
        w = set()
        ftype = file_type(fname)
        wc = 0
        if ftype == 'application/gzip' :
            f = gzip.open(fname, 'rt')
        elif ftype == 'text/plain' :
            f = open(fname, 'rt')
        else :
            assert 0, (fname, ftype)
        for l in f :
            l = l.strip().lower()
            if (not l) or l[0] == '#' :
                continue
            w.add(l)
            wc += 1
        f.close()
        trace("wordlist loaded: %s (%d words)" % (fname, wc))

        if blacklist :
            self.__blacklist.update(w)
        else :
            self.__words = tuple(sorted(set(self.__words).union(w)))


    # choice:
    #
    def choice (self, rand) :
        # all this is necessary to make sure that adding a forbidden
        # word does not change anything else in the passphrase
        w = rand.choice(self.__words)
        if w in self.__blacklist :
            st = rand.get_state()
            salt = [] # avoid a barely probable infinite loop ?
            while w in self.__blacklist :
                salt.append(rand.choice(CLASSES[rand.choice(CLASSES.keys())]))
                rand.seed(rand.getrandbits(512) ^ sha512bits(w, *salt))
                w = rand.choice(self.__words)
            rand.set_state(st)
        return w


    # generate:
    #
    def generate (self, sources) :
        info("generating words list (this may take a while)...")
        wlist = set()
        find = RE_WORD.findall
        scount = 0
        for src in sources :
            scount += 1
            #info("scanning source %s" % src)
            wl = set()
            for line in src :
                wl.update(w[1].lower() for w in find(line))
            wlist.update(wl)
            info("source: %s: %d words found (total: %d)" % (src, len(wl), len(wlist)))

        info("total found: %d words in %d sources" % (len(wlist), scount))
        self.__words = tuple(sorted(wlist))

        sample = MT().sample(wlist, min(len(wlist), 1000))
        sample.sort()
        for j in range(100) :
            for i in range(10) :
                idx = i * 100 + j
                sys.stdout.write('%-10s' % (sample[idx] if idx < len(sample) else '??'))
            sys.stdout.write('\n')


    # save:
    #
    def save (self, fname) :
        tmpfile = fname + '.tmp'
        fout = gzip.open(tmpfile, 'wt')
        fout.writelines(w+'\n' for w in self.__words)
        fout.close()
        os.rename(tmpfile, fname)


# primes:
#
# from http://vspike.wordpress.com/2010/10/15/blum-blum-shub-in-python/
# (itself from http://www.4dsolutions.net/cgi-bin/py2html.cgi?script=/ocn/python/primes.py)
#
# See the README file for more infos.
#
class primes (object) :


    # generate_n:
    #
    @staticmethod
    def generate_n (bits, nrand) :
        # [FIXME] changed bits/2 to bits//2 here, is it right ?
        p = primes.get_prime(bits//2, nrand)
        q = primes.get_prime(bits//2, nrand)
        while p == q :
            q = primes.get_prime(bits//2, nrand)
        return p * q


    # get_prime:
    #
    @staticmethod
    def get_prime (bits, nrand) :
        while True :
            p = primes.bigppr(bits, nrand)
            if p % 4 == 3 :
                break
        return p


    # bigppr:
    #
    @staticmethod
    def bigppr (bits, nrand) :
        assert isinstance(bits, int), bits # ?
        candidate = nrand.getrandbits(bits)
        if (candidate & 1) == 0 :
            candidate += 1
        prob = 0
        while True :
            prob = primes.pptest(candidate, nrand)
            if prob > 0 : break
            else : candidate += 2
        return candidate


    # pptest:
    #
    @staticmethod
    def pptest (n, nrand) :
        if n <= 1 :
            return 0

        bases = [nrand.randrange(2, 50000) for x in range(90)]
        for b in bases :
            if (n % b) == 0 :
                return 0
            
        tests, s, m = 0, 0, n-1
        while (m & 1) == 0 :
            m >>= 1
            s += 1

        for b in bases :
            tests += 1
            isprob = primes.algP(m, s, b, n)
            if not isprob :
                break

        if isprob :
            return (1 - (1.0 / (4**tests)))
        else :
            return 0


    # algP:
    #
    @staticmethod
    def algP (m, s, b, n) :
        result = 0
        y = pow(b, m, n)
        for j in range(s) :
            if (y == 1 and j == 0) or (y == (n - 1)) :
                result = 1
                break
            y = pow(y, 2, n)
        return result


# RNG:
#
# Base class for all the random number generators here.
#
class RNG :


    # test:
    #
    @classmethod
    def test (cls) :
        t = RNGTest(cls)
        t.run()


    # __init__:
    #
    def __init__ (self, seed) :
        self.__bits = 0
        self.__nbits = 0
        self.seed(seed)


    # seed:
    #
    # Note: base classes can override seed() if it makes sense but
    # _must_ chain to this one.
    #
    def seed (self, seed=None) :
        self.__bits, self.__nbits = 0, 0


    # get_state:
    #
    def get_state (self) :
        return (self.__bits, self.__nbits)


    # set_state:
    #
    def set_state (self, state) :
        self.__bits, self.__nbits = state


    # getrandbits:
    #
    def getrandbits (self, nbits) :
        if self.__nbits == 0 :
            self.__bits, self.__nbits = self.nextbits()
        r = 0
        while True :
            if nbits <= self.__nbits :
                r = (r << nbits) | (self.__bits & ((1 << nbits) - 1))
                self.__bits >>= nbits
                self.__nbits -= nbits
                return r
            else :
                r = (r << self.__nbits) | self.__bits
                nbits -= self.__nbits
                self.__bits, self.__nbits = self.nextbits()

        
    # randrange (low, high)
    # randrange (high)
    #
    # Produces a number in range [low, high)
    #
    def randrange (self, *args) :
        if len(args) == 1 : low, high = 0, args[0]
        else : low, high = args
        width = high - low
        assert width > 0, width
        if width == 1 :
            return low
        else :
            # [fixme] !?
            nbits = get_nbits(width) + 32
            return low + (self.getrandbits(nbits) * width) // (1 << nbits)


    # randint:
    #
    # Produces a number in range[low, high]
    #
    def randint (self, *args) :
        if len(args) == 1 : return self.randrange(args[0]+1)
        elif len(args) == 2 : return self.randrange(args[0], args[1]+1)
        else : assert 0, args


    # choice:
    #
    def choice (self, seq) :
        if not isinstance(seq, (list, tuple)) :
            seq = tuple(seq)
        return seq[self.randrange(len(seq))]


    # sample:
    #
    def sample (self, seq, n) :
        # [fixme] inefficient with big sets
        l = list(seq)
        r = []
        for x in range(n) :
            r.append(l.pop(self.randrange(len(l))))
        return r


# MT:
#
# from http://en.wikipedia.org/wiki/Mersenne_twister
#
#
class MT (RNG) :
                
        
    # __init__:
    #
    def __init__ (self, seed=None) :
        self.__mt = [None for n in range(624)]
        self.__idx = 0
        RNG.__init__(self, seed=seed)


    # seed:
    #
    def seed (self, seed=None) :
        if seed is None :
            seed = SysRand().getrandbits(32)
        RNG.seed(self, seed)
        # [fixme] try to use all the bits
        while get_nbits(seed) > 32 :
            seed = (seed & 0xffffffff) ^ (seed >> 32)
        self.__idx = 0
        mt = self.__mt
        mt[0] = seed
        for i in range(1, 624) :
            mt[i] = (0x6c078965 * (mt[i-1] ^ (mt[i-1] >> 30)) + i) & 0xffffffff


    # nextbits:
    #
    def nextbits (self) :
        if self.__idx == 0 :
            self.__gen()
        mt = self.__mt
        y = mt[self.__idx]
        y = y ^ (y >> 11)
        y = y ^ ((y << 7) & 0x9d2c5680)
        y = y ^ ((y << 15) & 0xefc60000)
        y = y ^ (y >> 18)
        self.__idx = (self.__idx + 1) % 624
        assert 0 <= y <= 0xffffffff, y # ?
        return y, 32


    # __gen:
    #
    def __gen (self) :
        mt = self.__mt
        for i in range(624) :
            y = (mt[i] & 0x80000000) + (mt[(i+1)%624] & 0x7fffffff)
            mt[i] = mt[(i+397)%624] ^ (y >> 1)
            if y & 1 :
                mt[i] = mt[i] ^ 0x9908b0df


# BBS:
#
# A Blum-Blum Shub PRNG,
#
# From http://vspike.wordpress.com/2010/10/15/blum-blum-shub-in-python/
# (itself from http://javarng.googlecode.com/svn/trunk/com/modp/random/BlumBlumShub.java)
#
# See the README file for more infos.
#
class BBS (RNG) :


    # __init__:
    #
    # 'nrand' is used to produce the N value.
    #
    def __init__ (self, **kw) :
        self.__init(**kw)

    def __init (self, seed=None, nrand=None) :
        self.__n = primes.generate_n(512, nrand)
        RNG.__init__(self, seed)


    # get_state:
    #
    def get_state (self) :
        return (RNG.get_state(self), self.__n, self.__state)


    # set_state:
    #
    def set_state (self, state) :
        istate, self.__n, self.__state = state
        RNG.set_state(istate)


    # seed:
    #
    def seed (self, seed=None) :
        assert seed is not None # [todo]
        RNG.seed(self, seed)
        self.__state = seed % self.__n


    # nextbits:
    #
    def nextbits (self) :
        s, n, r = self.__state, self.__n, 0
        for i in range(512) :
            s = (s ** 2) % n
            r = (r << 1) | (s & 1)
        self.__state, self.__n = s, n
        return r, 512


# SysRand:
#
# A 'real' random number generator which uses /dev/random (or
# /dev/urandom if urand is True in constructor). Accepts a seed for
# compatibility with other types but always ignores it!
#
class SysRand (RNG) :


    # __init__:
    #
    def __init__ (self, seed=None, urand=False) :
        self.__fname = '/dev/urandom' if urand else '/dev/random'
        RNG.__init__(self, seed=seed)


    # nextbits:
    #
    def nextbits (self) :
        nbits = 32 # always use a multiple of 8 !!
        nb = nbits // 8
        trace("reading %d bytes from '%s'" % (nb, self.__fname))
        f = open(self.__fname, 'rb')
        r = 0
        for n in range(nb) :
            b = f.read(1)
            r = (r << 8) | b[0]
            sys.stdout.write('.')
            sys.stdout.flush()
        f.close()
        sys.stdout.write('\n')
        sys.stdout.flush()
        return r, nbits


# RNGTest:
#
class RNGTest :
    

    # __init__:
    #
    def __init__ (self, rngclass) :
        self.__rngclass = rngclass


    # run:
    #
    def run (self) :
        names = [n for n in dir(self) if n.startswith('test_')]
        tests = [getattr(self, n) for n in sorted(names)]
        trace("%s: running %d tests" % (self.__rngclass.__name__, len(tests)))
        for t in tests :
            trace(" - %s" % t.__name__)
            t(self)

        
    # test_1:
    #
    def test_1 (self, rand) :
        NLOOPS = 100000
        mt = MT()
        for bits in (1, 8, 32, 37, 64) :
            nmin, nmax, nsum = 0x100000000, 0, 0
            bcount = [0 for b in range(bits)]
            for i in range(NLOOPS) :
                n = mt.getrandbits(bits)
                nmin = min(nmin, n)
                nmax = max(nmax, n)
                nsum += n
                b = 0
                while n :
                    if n & 1 :
                        bcount[b] += 1
                    n >>= 1
                    b += 1
                #trace(" - 0x%8x" % n)
            trace("%2d bits: min/max/avg: 0x%016x / 0x%016x / 0x%016x" % (bits, nmin, nmax, nsum / NLOOPS))
            bsum = sum(bcount)
            for b in range(bits) :
                sys.stdout.write(' %7.3f%%' % (bcount[b] / NLOOPS * 100.0))
                if (b % 8 == 7) or (b == (bits-1)) : sys.stdout.write('\n')

        # make sure equal seeds produce the same sequence
        mt2 = MT()
        for i in range(100) :
            seed = mt.getrandbits(32)
            mt2.seed(seed)
            s1 = [mt2.getrandbits(mt2.getrandbits(6)+1) for n in range(100)]
            for s in range(10) :
                mt2.seed(seed)
                s2 = [mt2.getrandbits(mt2.getrandbits(6)+1) for n in range(100)]
                assert s1 == s2, seed


# PassToolApp:
#
class PassToolApp (object) :


    # main
    #
    def main (self) :
        try:
            self.real_main()
        except Exception:
            print_exception()
            sys.exit(1)


    # real_main:
    #
    def real_main (self) :
        global ENABLE_DEBUG
        
        self.config = Config()
        
        # parse the command line
        cmd = ''
        shortopts = 'hgGPWrRkK:f:s:'
        longopts = ['help', 'gen-passwords', 'gen-passphrases', 'gen-wordlist',
                    'rand', 'urand', 'key', 'private-key=', 'file=', 'salt=']
        opts, args = getopt.gnu_getopt(sys.argv[1:], shortopts, longopts)
        for o, a in opts :
            if o in ('-h', '--help') :
                sys.stdout.write(USAGE)
                sys.exit(0)
            elif o in ('-g',) :
                ENABLE_DEBUG = True
            elif o in ('--mt-test',) :
                MT.test()
                sys.exit(0)
            elif o in('--bbs-test',) :
                BBS.test()
                sys.exit(0)
            elif o in ('-G', '--gen-password') :
                assert not cmd
                cmd = 'gen-passwords'
                self.config.passphrases = False
            elif o in ('-P', '--gen-passphrases') :
                assert not cmd
                cmd = 'gen-passwords'
                self.config.passphrases = True
            elif o in ('-W', '--gen-word-list') :
                assert not cmd
                cmd = 'gen-wordlist'
            elif o in ('-w', '--word-list') :
                self.config.wordlist = a
            elif o in ('-f', '--file') :
                self.config.input_files += ':' + a
            elif o in ('-r', '--rand') :
                self.config.rand_source = 'rand'
            elif o in ('-R', '--urand') :
                self.config.rand_source = 'urand'
            elif o in ('-k', '--key') :
                self.config.rand_source = 'key'
            elif o in ('-K', '--private-key') :
                self.config.private_key = a
            elif o in ('-s', '--salt') :
                self.config.cmd_salt = a
            else :
                assert 0, (o, a)

        # [fixme]
        self.config.names = list(args)

        # read the config file(s)
        self.read_config()

        # go
        if cmd == 'gen-wordlist' :
            wl = WordList()
            info("generating word list (this may take a while) ...")
            wl.generate(WordSourceFile(a) for a in args) # [fixme]
            info("%d words found, saving list in '%s'" %
                 (wl.nwords, self.config.wordlist))
            wl.save(self.config.wordlist)
            info("all done!")
        elif cmd in ('', 'gen-passwords') :
            self.generate_passwords()
        else :
            pass #assert 0, cmd


    # generate_passwords:
    #
    def generate_passwords (self) :
        trace("generating passwords (salt: '%s/%s/%s')" %
              (self.config.sys_salt, self.config.usr_salt, self.config.cmd_salt))
        
        # create the wordlist
        wordlist = WordList()
        wordlist.read_file(os.path.join(self.config.usrcfgdir, 'wordlist.gz'))
        wordlist.read_file(os.path.join(self.config.usrcfgdir, 'blacklist.txt'), blacklist=True)
        info("wordlist(s) loaded: %d words (%d forbidden, %d usable)" %
             (wordlist.nwords, wordlist.nforbidden, wordlist.nusable))

        # make the names list
        names = list(self.parse_names())
        
        # make a 512 bits seed, 'safely' or from the user key
        hkey = self.get_hkey()
        trace("HKEY:\n %064x\n %064x" %
              (hkey >> 256, hkey & ((1 << 256) - 1)))

        # create the rand generator (with a dumb seed to avoid a call
        # to SysRand as the correct seed will be given later)
        rand = BBS(seed=1, nrand=MT(seed=hkey))

        # make the passwords list
        pwlist = []
        for nloc, nspec, ident, salt, name, opts in names :
            opts = opts.copy()
            # trace(" -> %s/%s (%s) : %s" % (ident, salt, name, opts))
            dophrase = opts.pop('passphrase', self.config.passphrases)
            min_chars = int(opts.pop('pwmnc', self.config.min_chars))
            max_chars = int(opts.pop('pwmxc', self.config.max_chars))
            char_classes = [c.strip() for c in opts.pop('pwcls', self.config.char_classes).split(',')]
            min_words = int(opts.pop('ppmnw', self.config.min_words))
            max_words = int(opts.pop('ppmxw', self.config.max_words))
            sep_classes = [c.strip() for c in opts.pop('ppcls', self.config.sep_classes).split(',')]
            case_type = opts.pop('ppcase', self.config.case_type)
            if opts :
                error("%s:%d: invalid option(s): '%s'" %
                      (nloc[0], nloc[1], '/'.join('%s=%s' % i for i in opts.items())))

            if name == '-' :
                pwlist.append(('-', ''))
            else :
                hident = sha512bits(ident, self.config.sys_salt, self.config.usr_salt, self.config.cmd_salt, salt)
                rand.seed(hkey ^ hident)

                if dophrase :
                    pwd = self.gen_pp(rand, wordlist, min_words=min_words, max_words=max_words,
                                      sep_classes=sep_classes, case_type=case_type)
                else :
                    pwd = self.gen_pw(rand, min_chars=min_chars, max_chars=max_chars,
                                      char_classes=char_classes)
                pwlist.append((name, pwd))


        # output
        cwidth = tuple(max(len(l[i]) for l in pwlist) for i in range(2))
        sep = '+' + ('-' * (cwidth[0]+2)) + '+' + ('-' * (cwidth[1]+2)) + '+'
        print(sep)
        for name, pwd in pwlist :
            if name == '-' :
                print(sep)
            else :
                fmt = '| %%-%ds | %%-%ds |' % cwidth
                print(fmt % (name, pwd))
        print(sep)


    # gen_pw:
    #
    def gen_pw (self, rand, min_chars, max_chars, char_classes) :
        nchars = rand.randint(min_chars, max_chars) \
          if min_chars < max_chars else min_chars
            
        letters = list(char_classes)
        while len(letters) < nchars :
            letters.append(rand.choice(char_classes))
        pw = ''
        while letters :
            l = letters.pop(rand.randrange(0, len(letters)))
            pw += rand.choice(CLASSES[l])
        return pw


    # gen_pp:
    #
    def gen_pp (self, rand, wordlist, min_words, max_words, sep_classes, case_type) :
        nwords = rand.randint(min_words, max_words) \
          if min_words < max_words else min_words
        words = [wordlist.choice(rand) for n in range(nwords)]
        seps = [rand.choice(CLASSES[rand.choice(sep_classes)])
                for n in range(nwords-1)]
        pp = ''
        if case_type == 'rand' :
            case_type = rand.choice(('cap', 'low', 'up'))
        for i, w in enumerate(words) :
            if case_type == 'cap' : w = w.capitalize()
            elif case_type == 'low' : w = w.lower()
            elif case_type == 'up' : w = w.upper()
            else : error("invalid case_type: '%s'" % case_type)
            pp += w
            if i < (nwords-1) :
                pp += seps[i]
        return ''.join(pp)


    # parse_names:
    #
    def parse_names (self) :
        names = [(('<input>', 0), n) for n in list(self.config.names)]
        flist = self.config.get_vstr('input_files', ':')
        if not (names or flist) :
            flist.append(os.path.join(self.config.usrcfgdir, 'passnames.txt'))
        for fname in flist :
            names.extend(((fname, lno+1), l)
                         for lno, l in enumerate(open(fname, 'rt').readlines()))

        stack = [{}]
        match = RE_NAMESPEC.match
        matchopt = RE_NSPECOPT.match
        for (nfn, nln), nspec in names :
            m = match(nspec)
            if m is None :
                error("%s:%d: invalid name: '%s'" % (nfn, nln, nspec.strip()))
                continue
            nopts, nid, nsalt, nname, ncom = m.group('OPTS', 'ID', 'SALT', 'NAME', 'COM')
            if not nid :
                assert not (nsalt or nname), nspec # ?
                if not nopts : continue # blank line
                nid = ''
            if not nsalt : nsalt = ''
            if not nname : nname = nid
                
            # trace("NSPEC: '%s'" % nspec.replace('\n', '\\n'))
            # trace(" - OPTS:   '%s'" % nopts)
            # trace(" - ID:     '%s'" % nid)
            # trace(" - SALT:   '%s'" % nsalt)
            # trace(" - NAME:   '%s'" % nname)
            # trace(" - COM:    '%s'" % ncom)

            opts = self.__parse_opts(nopts, stack)
            # trace(" - OPTDICT:\n%s" % '\n'.join("   - '%s' = '%s'" % i for i in opts.items()))
            if nid :
                yield (nfn, nln), nspec, nid, nsalt, nname, opts


    # __parse_opts:
    #
    def __parse_opts (self, nopts, stack) :
        if nopts is None :
            return stack[-1].copy()
        opts = {}
        match = RE_NSPECOPT.match
        pos = 0
        nlen = len(nopts)
        push, pop = False, False
        while pos < nlen :
            m = match(nopts, pos)
            if m is None :
                assert 0, nopts[pos:]
            onot, oname, ovalue = m.group('NOT', 'NAME', 'VALUE')
            pos = m.end()
            # special names
            if oname == 'push' :
                push = True
                continue
            elif oname == 'pop' :
                pop = True
                continue
            elif oname == '*' :
                assert ovalue is None
                oname = 'passphrase'
            # fix value
            if onot :
                assert ovalue is None
                val = False
            elif ovalue is None :
                val = True
            else :
                val = ovalue
            # set
            opts[oname] = val

        if pop : stack.pop()
        opts2 = stack[-1].copy()
        opts2.update(opts)
        if push : stack.append(opts2.copy())
        return opts2


    # read_config:
    #
    # Read all the config files we can find.
    #
    def read_config (self) :
        flist = [os.path.join(self.config.usrcfgdir, 'passtool.conf')]
        self.config.read_file_list(flist)


    # get_hkey:
    #
    # Get some 512 bits key from the source selected by the user.
    #
    def get_hkey (self) :
        s = self.config.rand_source
        if s == 'rand' :
            hkey = self.__read_rand_bytes('/dev/random')
        elif s == 'urand' :
            hkey = self.__read_rand_bytes('/dev/urandom')
        elif s == 'key' :
            if self.config.private_key  :
                warn("giving the private key on command line is unsafe!")
                key = self.config.private_key
            else :
                key = self.input_key()
            hkey = sha512bits(key) # [fixme] salt ?
        else :
            assert 0, s
        return hkey


    # input_key:
    #
    def input_key (self) :
        while True :
            k1 = getpass.getpass("Enter your password/passphrase:")
            k2 = getpass.getpass("Re-enter your password/passphrase:")
            if k1 == k2 :
                return k1
            else :
                error("passwords mismatch!")


    # [fixme] use SysRand now
    def __read_rand_bytes (self, fname) :
        info("reading 64 bytes from '%s'" % fname)
        f = open(fname, 'rb')
        hkey = 0
        for i in range(64) :
            b = f.read(1)
            hkey = (hkey << 8) | b[0]
            sys.stdout.write('.')
            sys.stdout.flush()
        sys.stdout.write('\n')
        f.close()
        return hkey

                
# exec
if __name__ == '__main__' :
    app = PassToolApp()
    app.main()
