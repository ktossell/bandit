import re

TIMESTAMP_RE = re.compile(r'^\[(\d+-\d+-\d+\s+\d+:\d+:\d+)\] (.+)$')

def timestamped_deriv_filter(deriv):
    def filtered(line):
        m = TIMESTAMP_RE.match(line)
        if m:
            res = deriv(m.group(2))
            if res:
                return (m.group(1), res)

    return filtered

