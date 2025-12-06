#!/usr/bin/env python

import sys
import os
import re
import json
import zipfile
from io import BytesIO
from pathlib import Path

from anchore import anchore_utils
analyzer_name = "package_list"

try:
    config = anchore_utils.init_analyzer_cmdline(sys.argv, analyzer_name)
except Exception as err:
    print (str(err))
    sys.exit(1)

imgname = config['imgid']
imgid = config['imgid_full']
outputdir = config['dirs']['outputdir']
unpackdir = config['dirs']['unpackdir']

def process_java_archive(prefix, filename, inZFH):
    ret = []

    
    fullpath =  Path(prefix) / filename

    jtype = None
    patt = re.match(r".*\.(jar|war|ear)", fullpath)
    if patt:
        jtype = patt.group(1)
    else:
        return([])
    name = re.sub(r"\."+jtype+"$", "", fullpath.split("/")[-1])

    top_el = {}
    sub_els = []
    try:

        # set up the zipfile handle
        try:
            if not inZFH:
                if zipfile.is_zipfile(fullpath):
                    ZFH = zipfile.ZipFile(fullpath, 'r')
                    location = filename
                else:
                    return([])
            else:
                zdata = BytesIO( inZFH.read() )
                ZFH = zipfile.ZipFile(zdata, 'r')
                location = prefix + ":" + filename
    
        except Exception as err:
            raise err

        top_el = {
            'metadata':{},
            'specification-version': "N/A",
            'implementation-version': "N/A",
            'origin': "N/A",
            'location': "N/A",
            'type': "N/A"
        }
        top_el['location'] = location 
        top_el['type'] = "java-"+str(jtype)
        top_el['name'] = name

        sname = sversion = svendor = iname = iversion = ivendor = mname = None
    
        try:
            with ZFH.open('META-INF/MANIFEST.MF', 'r') as MFH:
                top_el['metadata']['MANIFEST.MF'] = MFH.read()

            for line in top_el['metadata']['MANIFEST.MF'].splitlines():
                try:
                    (k,v) = line.split(": ", 1)
                    if k == 'Specification-Title':
                        sname = v
                    elif k == 'Specification-Version':
                        sversion = v
                    elif k == 'Specification-Vendor':
                        svendor = v
                    elif k == 'Implementation-Title':
                        iname = v
                    elif k == 'Implementation-Version':
                        iversion = v
                    elif k == 'Implementation-Vendor':
                        ivendor = v
                except:
                    pass

            if sversion:
                top_el['specification-version'] = sversion
            if iversion:
                top_el['implementation-version'] = iversion

            if svendor:
                top_el['origin'] = svendor
            elif ivendor:
                top_el['origin'] = ivendor

        except:
            # no manifest could be parsed out, leave the el values unset
            pass

        for zfname in ZFH.namelist():
            sub_jtype = None
            patt = re.match(r".*\.(jar|war|ear)", zfname)
            if patt:
                sub_jtype = patt.group(1)

            if sub_jtype:
                ZZFH = None
                try:
                    ZZFH = ZFH.open(zfname, 'r')
                    sub_els = sub_els + process_java_archive(location, zfname, ZZFH)
                except Exception as err:
                    pass
                finally:
                    if ZZFH:
                        ZZFH.close()
            
    except Exception as err:
        raise err
    finally:
        if inZFH:
            try:
                inZFH.close()
            except:
                pass

    ret = [top_el]
    if sub_els:
        ret = ret + sub_els

    return(ret)

resultlist = {}
try:
    allfiles = {}
    (Path(unpackdir) / 'anchore_allfiles.json')
    if os.path.exists((Path(unpackdir) / 'anchore_allfiles.json')):
        with open((Path(unpackdir) / 'anchore_allfiles.json'), 'r') as FH:
            allfiles = json.loads(FH.read())
    else:
        
        fmap, allfiles = anchore_utils.get_files_from_path((Path(unpackdir) / 'rootfs'))
        with open((Path(unpackdir) / 'anchore_allfiles.json'), 'w') as OFH:
            OFH.write(json.dumps(allfiles))

    for f in allfiles.keys():
        if allfiles[f]['type'] == 'file':
            prefix = Path(unpackdir) / 'rootfs'
            els = process_java_archive(prefix, f.encode('utf8'), None)
            if els:
                for el in els:
                    resultlist[el['location']] = json.dumps(el)

except Exception as err:
    print("WARN: analyzer unable to complete - exception: " + str(err))

if resultlist:
    ofile = Path(outputdir) / 'pkgs.java'
    anchore_utils.write_kvfile_fromdict(ofile, resultlist)

sys.exit(0)
