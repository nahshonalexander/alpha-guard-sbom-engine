#!/usr/bin/env python

import sys
import os
import anchore_utils


analyzer_name = "ANALYZER_NAME"

try:
    config = anchore_utils.init_analyzer_cmdline(sys.argv, analyzer_name)
except Exception as err:
    print(str(err))
    sys.exit(1)

imgname = config['imgid']
outputdir = config['dirs']['outputdir']
unpackdir = config['dirs']['unpackdir']

if not os.path.exists(outputdir):
    os.makedirs(outputdir)

