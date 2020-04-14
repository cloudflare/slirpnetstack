import itertools
import math
import re
import shlex
import string
import socket


IP_FREEBIND = 15

def test_encode_shell():
    a = shlex.split(encode_shell(['a', 'b', 'c']))
    assert a == ['a', 'b', 'c']
    a = shlex.split(encode_shell(['\\a', '!b', '\tc']))
    assert a == ['\\a', '!b', '\tc']
    a = shlex.split(encode_shell(['\\a \tc']))
    assert a == ['\\a \tc']
    a = shlex.split(encode_shell(['"\'']))
    assert a == ['"\''], repr(a)
    a = shlex.split(encode_shell(['"abc']))
    assert a == ['"abc']
    a = shlex.split(encode_shell(["'abc\""]))
    assert a == ["'abc\""]
    a = shlex.split('--test="masala chicken" --test=\'chicken masala\'')
    assert a == ["--test=masala chicken", "--test=chicken masala"]
    a = encode_shell(['--test=masala chicken', '--test=chicken masala'])
    assert a == "--test='masala chicken' --test='chicken masala'"


# The opposite of shlex.split(). It doesn't matter how the stuff is
# going to be encoded, as long as shlex() and potentially bash will
# parse it the same way. With regard to tabs and special chars we
# kindof lost, as passing them via bash is hard. But we should make
# sure at least quotes and spaces work as intended.
#
# Thre is a special exception for parsing --param=argument syntax.
# Although technicall sound, most likely you don't want to encode it
# like that: ' "--param=the argument" ', you most likely want:
# '--pram="the argument"', so there's an exception for it.

PARAM = re.compile('^--(?P<opt>[a-z_-]+)[ =](?P<rest>.*)$')
ACCEPTABLE_CHARS = set(string.printable) - set(string.whitespace) - set("'\"\\&#!`()[]{}$|")

def encode_shell(params):
    r'''
    >>> test_encode_shell()
    '''
    s = []
    for token in params:
        m = PARAM.match(token)
        if m:
            m = m.groupdict()
            token = m['rest']
        if not set(token) - ACCEPTABLE_CHARS:
            enc_token = token
        else:
            if "'" not in token:
                enc_token = "'" + token + "'"
            else:
                t = token.replace('`', '\\`').replace('"', '\\"')
                enc_token = '"' + t + '"'
        if not m:
            s.append(enc_token)
        else:
            s.append('--%s=%s' % (m['opt'], enc_token))
    return ' '.join(s)



def connect(ip='127.0.0.1', port=0, path=None, udp=False, src='', sport=0,
            cloexec=True, cleanup=None, timeout=2):
    if udp == False:
        p = socket.SOCK_STREAM
    else:
        p = socket.SOCK_DGRAM

    if path:
        s = socket.socket(socket.AF_UNIX, p)
    elif len(ip.split(':')) <= 2:
        s = socket.socket(socket.AF_INET, p)
    else:
        s = socket.socket(socket.AF_INET6, p)

    if cleanup:
        cleanup.addCleanup(s.close)

    s.set_inheritable(not cloexec)

    if src or sport > 0:
        s.setsockopt(socket.IPPROTO_IP, IP_FREEBIND, 1)
        s.bind((src, sport))

    # to make tests fail, instead of halt indefintely, let's set the
    # default timeout to say 2 sec.
    s.settimeout(timeout)

    try:
        if not path:
            s.connect((ip, port))
        else:
            path = path.replace("@", "\x00")
            s.connect(path)
    except socket.timeout as e:
        s.close()
        raise e

    return s
