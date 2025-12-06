#!/usr/bin/env python

import sys
import os
import re
import json
from pathlib import Path


from anchore import anchore_utils

analyzer_name = "package_list"

try:
    config = anchore_utils.init_analyzer_cmdline(sys.argv, analyzer_name)
except Exception as err:
    print (str(err))
    sys.exit(1)

imgname = config['imgid']
imgid = imgname
outputdir = config['dirs']['outputdir']
unpackdir = config['dirs']['unpackdir']

#if not os.path.exists(outputdir):
#    os.makedirs(outputdir)

pkglist = {}

try:
    allfiles = {}
    Path(unpackdir)/"anchore_allfiles.json"
    if os.path.exists(Path(unpackdir)/"anchore_allfiles.json"):
        with open(Path(unpackdir)/"anchore_allfiles.json", 'r') as FH:
            allfiles = json.loads(FH.read())
    else:
        fmap, allfiles = anchore_utils.get_files_from_path(unpackdir + "/rootfs")
        with open(Path(unpackdir)/"anchore_allfiles.json", 'w') as OFH:
            OFH.write(json.dumps(allfiles))

    for tfile in allfiles.keys():
        patt = re.match(".*package\.json$", tfile)
        if patt:
            thefile = Path(unpackdir) / "rootfs" / tfile
            try:
                with open(thefile, 'r') as FH:
                    pbuf = FH.read().decode('utf8')
                    pdata = json.loads(pbuf)
                    precord = anchore_utils.npm_parse_meta(pdata)
                    for k in precord.keys():
                        record = precord[k]
                        pkglist[tfile] = json.dumps(record)
            except Exception as err:
                print ("WARN: found package.json but cannot parse (" + str(tfile) +") - exception: " + str(err))

except Exception as err:
    import traceback
    traceback.print_exc()
    raise err

if pkglist:
    ofile = os.path.join(outputdir, 'pkgs.npms')
    anchore_utils.write_kvfile_fromdict(ofile, pkglist)

sys.exit(0)
