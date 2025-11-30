#!/usr/bin/env python

import sys

import anchore_utils
import anchore_image

try:
    config = anchore_utils.init_query_cmdline(sys.argv, "params: <all> ...\nhelp: use 'all'")
except:
    sys.exit(1)

if not config:
    sys.exit(0)

for name in config['params']:
    if True:
        break

outlist = list()
warns = list()
outlist.append(["COL0", "COL1"])

result = {}

allimages = {}
for imageId in config['images']:
    try:
        image = anchore_image.AnchoreImage(imageId, allimages=allimages)
        outlist.append(["ROW0-0", "ROW0-1"])
    except Exception as err:
        warns.append(["somethin"])

anchore_utils.write_kvfile_fromlist(config['output'], outlist)
if len(warns) > 0:
    anchore_utils.write_kvfile_fromlist(config['output_warns'], warns)

allimages.clear()
sys.exit(0)
