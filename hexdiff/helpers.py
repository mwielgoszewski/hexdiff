# -*- coding: utf-8 -*-
'''
hexdiff.helpers
~~~~~~~~~~~~~~~

'''
from difflib import SequenceMatcher
from itertools import combinations
import string


FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
ALNUMS = string.letters + string.digits + '. '


def escape(s):
    return ''.join([(ch in ALNUMS) and ch or "&#%d;" % ord(ch) for ch in s])


def hexdump(data, out=False):
    lno = 0
    output = []
    data = bytearray(data)

    while data:
        line, data = data[:16], data[16:]
        output.append((lno, ['%02x' % x for x in line], str(line.translate(FILTER))))
        lno += 16

    return output


def colorize(dump, idx, size, color):
    if size == 0:
        return dump

    s_line = (idx / 16)
    f_line = ((idx + size) / 16)

    _idx = (idx % 16)
    _end = ((idx + size) % 16) - 1

    if s_line == f_line:
        dump[s_line][1][_idx] = '<span class="c%d">%s' % (color, dump[s_line][1][_idx], )
        dump[f_line][1][_end] += '</span>'
        return dump

    dump[s_line][1][_idx] = '<span class="c%d">%s' % (color, dump[s_line][1][_idx], )
    dump[s_line][1][-1] += '</span>'

    # span lines non-inclusive of start and finish
    for spanned_line in xrange(s_line + 1, f_line):
        dump[spanned_line][1][0] = '<span class="c%d">%s' % (color, dump[spanned_line][1][0], )
        dump[spanned_line][1][-1] += '</span>'

    if _end != -1:
        dump[f_line][1][0] = '<span class="c%d">%s' % (color, dump[f_line][1][0], )
        dump[f_line][1][_end] += '</span>'

    return dump


def diff2html(dump_a, dump_b, matches):
    for color, match in enumerate(matches):
        colorize(dump_a, match.a, match.size, color)
        colorize(dump_b, match.b, match.size, color)

    def redump(dump):
        out = "<pre>"
        for n, bits, line in dump:
            if len(bits) != 16:
                bits.extend([' &nbsp;' for i in xrange(16 - len(bits))])
            out += "0x%08x:  %-47s |%-16s|\n" % (n, ' '.join(bits), escape(line))
        return out.rstrip() + "</pre>"

    return redump(dump_a), redump(dump_b)


def analyze(minlength=2, encode=str, decode=str, *tokens):
    """
    :param minlength: Minimum length of matching block to render.
    :param decode: Decode function, default is str().
    :param encode: Encode function, default is str().
    """
    results = []
    decoded = set(map(decode, tokens))

    current = None
    longest_match = 0
    matcher = SequenceMatcher(None)

    # Combine every token against every other token...
    for base, comp in combinations(decoded, 2):
        matcher.set_seq1(comp)

        if base != current:
            current = base
            enc_current = encode(current)

            # SequenceMatcher computes and caches detailed information.
            # about the second sequence, so comparing one sequence against
            # many, it's more efficient to set_seq2() on the base sequence
            # that's compared against many.
            matcher.set_seq2(base)

        matches = matcher.get_matching_blocks()
        matches = [m for m in matches if m.size > minlength]

        if len(matches) > longest_match:
            longest_match = len(matches)

        # sort by size, longest to shortest
        matches.sort(key=lambda x:x.size, reverse=True)

        results.append((matcher.ratio(), encode(comp), enc_current,
                        diff2html(hexdump(comp), hexdump(base), matches)))

    return results, longest_match
