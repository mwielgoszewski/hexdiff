# -*- coding: utf-8 -*-
'''
hexdiff.core
~~~~~~~~~~~~

'''
from .helpers import analyze
from itertools import cycle, islice

from flask import Flask, render_template, request


app = Flask(__name__)


@app.route('/')
@app.route('/compare', methods=['GET', 'POST'])
def hexdiff():
    if request.method == 'GET':
        return render_template('hexdiff.html')

    tokenA = bytearray(try_decode(request.form['tokenA']))
    tokenB = bytearray(try_decode(request.form['tokenB']))

    results, longest_match = analyze(2, str, str, tokenA, tokenB)

    colors = ('ef2929', 'f57900', 'fce94f', '8ae234', '4e9a06', '729fcf', '204a87', '5c3566')

    styles = ['.c%d{background-color:#%s;}' % (i, c) for i, c in enumerate(islice(cycle(colors), longest_match))]
    styles.extend(['th{font-size:.8em;}',
        'table{border:2px solid #000;border-collapse:collapse;}',
        'td{border:2px solid #000;padding:4px;}'
        'td.colA,td.colB{font-size:.9em;}',
        '.tknLnk{font:normal 1em monospace;}',
        '.ratio,.tknId{font-size:.8em;}'])
    
    return render_template('hexdiff.html', results=results, styles='\n  '.join(styles))


def try_decode(data):
    try:
        return data.decode('hex')
    except TypeError:
        try:
            return data.decode('base64')
        except Exception:
            return str(data)
