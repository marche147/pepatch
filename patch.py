#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from __future__ import print_function
import sys
import argparse
from core.patcher import Patcher
import os

parser = argparse.ArgumentParser("A hacky tool for PE patching.")
parser.add_argument('target', help="target file being patched")
parser.add_argument('patchscript', help="patcher script")
parser.add_argument("-o", nargs=1, help="output file path", action='store', dest='output', default=None, metavar=('output_file'))
parser.add_argument("--cflags", nargs='+', help="cflags passed to the compiler", dest='cflags')

def main(argv):
    args = parser.parse_args(argv[1:])
    target = args.target
    dirname = os.path.dirname(args.patchscript)
    sys.path.insert(0, dirname)
    patchscript = os.path.basename(args.patchscript).rstrip('.py')
    output = args.output
    if not output:
        output = target + '.patched'
    cflags = args.cflags

    patcher = Patcher(target, cflags)
    # do it
    getattr(__import__(patchscript), 'patch')(patcher)

    patcher.save(output)
    return 0

sys.exit(main(sys.argv))
