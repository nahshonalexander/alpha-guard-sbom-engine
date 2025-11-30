#!/usr/bin/env python

import sys
import os


import anchore_utils

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

meta = anchore_utils.get_distro_from_path('/'.join([unpackdir, "rootfs"]))
distrodict = anchore_utils.get_distro_flavor(meta['DISTRO'], meta['DISTROVERS'], likedistro=meta['LIKEDISTRO'])

print ("analyzer starting up: imageId="+str(imgid) + " meta="+str(meta) + " distrodict="+str(distrodict))

if distrodict['flavor'] not in ['RHEL', 'DEB', 'BUSYB', 'ALPINE']:
    sys.exit(0)

pkgsall = {}
pkgfilesall = {}
pkgsplussource = {}

if distrodict['flavor'] == "RHEL":
    try:
        rpms = anchore_utils.rpm_get_all_packages(unpackdir)
        for pkg in rpms.keys():
            pkgsall[pkg] = rpms[pkg]['version'] + "-" + rpms[pkg]['release']
    except Exception as err:
        print ("WARN: failed to generate RPM package list: " + str(err))

    try:
        rpmfiles = anchore_utils.rpm_get_all_pkgfiles(unpackdir)
        for pkgfile in rpmfiles.keys():
            pkgfilesall[pkgfile] = "RPMFILE"
    except Exception as err:
        print ("WARN: failed to get file list from RPMs: " + str(err))

elif distrodict['flavor'] == "DEB":
    try:
        (all_packages, actual_packages, other_packages) = anchore_utils.dpkg_get_all_packages(unpackdir)
    
        for p in actual_packages.keys():
            pkgsall[p] = actual_packages[p]['version']

        for p in all_packages.keys():
            pkgsplussource[p] = all_packages[p]['version']

        if len(other_packages) > 0:
            for p in other_packages.keys():
                for v in other_packages[p]:
                    pkgsplussource[p] = v['version']
    except Exception as err:
        print("WARN: failed to get package list from DPKG: " + str(err))

    try:
        dpkgfiles = anchore_utils.dpkg_get_all_pkgfiles(unpackdir)
        for pkgfile in dpkgfiles.keys():
            pkgfilesall[pkgfile] = "DPKGFILE"

    except Exception as err:
        print("WARN: failed to get file list from DPKGs: " + str(err))

elif distrodict['flavor'] == 'ALPINE':
    try:
        apkgs = anchore_utils.apkg_get_all_pkgfiles(unpackdir)
        for pkg in apkgs.keys():
            # base
            if apkgs[pkg]['release'] != "N/A":
                pvers = apkgs[pkg]['version']+"-"+apkgs[pkg]['release']
                #pkgsall[pkg] = apkgs[pkg]['version']+"-"+apkgs[pkg]['release']
            else:
                pvers = apkgs[pkg]['version']
                #pkgsall[pkg] = apkgs[pkg]['version']
            pkgsall[pkg] = pvers
            pkgsplussource[pkg] = pvers

            # source package
            if 'sourcepkg' in apkgs[pkg] and apkgs[pkg]['sourcepkg']:
                spkg = apkgs[pkg]['sourcepkg']
                if spkg != pkg and spkg not in pkgsplussource:
                    pkgsplussource[spkg] = pvers

            # pkgfiles
            for pkgfile in apkgs[pkg]['files']:
                pkgfilesall[pkgfile] = 'APKFILE'

    except Exception as err:
        print ("WARN: failed to generate APK package list: " + str(err))

elif distrodict['flavor'] == "BUSYB":
    pkgsall["BusyBox"] = distrodict['fullversion']
else:
    pkgsall["Unknown"] = "0"

if pkgsall:
    ofile = os.path.join(outputdir, 'pkgs.all')
    anchore_utils.write_kvfile_fromdict(ofile, pkgsall)
    #anchore.anchore_utils.save_analysis_output(imgid, 'package_list', 'pkgs.all', pkgsall)
if pkgfilesall:
    ofile = os.path.join(outputdir, 'pkgfiles.all')
    anchore_utils.write_kvfile_fromdict(ofile, pkgfilesall)
    #anchore.anchore_utils.save_analysis_output(imgid, 'package_list', 'pkgfiles.all', pkgfilesall)
if pkgsplussource:
    ofile = os.path.join(outputdir, 'pkgs_plus_source.all')
    anchore_utils.write_kvfile_fromdict(ofile, pkgsplussource)
    #anchore.anchore_utils.save_analysis_output(imgid, 'package_list', 'pkgs_plus_source.all', pkgsplussource)

sys.exit(0)
