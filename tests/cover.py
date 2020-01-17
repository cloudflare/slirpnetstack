#!/usr/bin/env python3
import argparse
import collections
import re
import sys


class Cover(object):
    def __init__(self):
        self.t = []

    def extend(self, vmax):
        delta = vmax - len(self.t)
        if delta > 0:
            self.t += [None] * delta

    def clear(self, start, stop):
        self.extend(stop+1)
        for x in range(start, stop+1):
            if self.t[x] is None:
                self.t[x] = False

    def mark(self, start, stop):
        self.extend(stop+1)
        for x in range(start, stop+1):
            self.t[x] = True

    def list(self, state):
        p = not state
        start = 0
        for i, v in enumerate(self.t):
            if p != state and v == state:
                p = state
                start = i
            elif p == state and v != state:
                p = not state
                yield (start, i-1)
        if p == state:
            yield (start, i-1)

    def count(self):
        tot = sum(map(lambda x: x!= None, self.t))
        true = sum(map(lambda x: x == True, self.t))
        return tot-true, tot


def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=r'''
Merges and pretty prints golang coverage files.
''')

    parser.add_argument('file', nargs='*',
                        help='golang coverage.out file')

    parser.add_argument('--missing', action='store_true',
                        help='list missed lines')

    parser.add_argument('-q', '--quiet', action='store_true',
                        help='just summary')

    parser.add_argument('--size', action='store_true',
                        help='order missing blocks by size')

    args = parser.parse_args()

    files = collections.defaultdict(Cover)

    LINE = re.compile('^(?P<fname>.*):(?P<start_line>\d+).(?P<start_col>\d+),(?P<stop_line>\d+).(?P<stop_col>\d+) (?P<c>\d+) (?P<covered>\d+)$')

    for fname in args.file:
        with open(fname, 'r') as fd:
            for line in fd:
                if line.startswith('mode:'):
                    continue
                m = LINE.match(line).groupdict()
                c = files[m['fname']]
                start, stop = int(m['start_line']), int(m['stop_line'])
                if m['covered'] == '1':
                    c.mark(start, stop)
                else:
                    c.clear(start, stop)

    x = max(map(len, files.keys()))

    head = "Name%s Stmts   Miss  Cover" % (' ' * (x-2))
    if args.missing:
        head += "   Missing"
    print(head)

    if not args.quiet:
        print("-" * len(head))

    tot_bad, tot_tot = 0, 0
    for t in sorted(files.keys()):
        bad, tot = files[t].count()
        if not args.quiet:
            if args.missing:
                miss = list(files[t].list(False))
                if args.size:
                    miss.sort(key=lambda a,b:b-a, reverse=True)
                xx = ['%s-%s' % (a,b) if a != b else str(a) for a, b in miss]
            else:
                xx = ''
            print('%-*s %7i%7i  %4i%%   %s' % (
                x, t, tot, bad,
                ((tot - bad) * 100.) / tot,
                ', '.join(xx)))
        tot_bad += bad
        tot_tot += tot

    print("-" * len(head))
    print('%-*s %7i%7i  %4i%%' % (x, 'TOTAL', tot_tot, tot_bad,
                                  ((tot_tot - tot_bad) * 100.) / tot_tot))


if __name__ == "__main__":
    main()
