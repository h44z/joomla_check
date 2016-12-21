#!/usr/bin/env python3

from pathlib import Path
import re
import urllib.request
from distutils.version import StrictVersion

##############################################################
## CONFIG
##############################################################

# BASE BASE
base_path = '/var/www/vhosts'

# CSV FILENAME
csv_file_name = 'joomla_status.csv'

#############################################################

def get_joomla_version(filepath):
    fobj = open(filepath, "r", -1, None, 'replace')
    version = -1
    dev_version = -1
    for line in fobj:
        if version != -1 and dev_version != -1:
            break

        match = re.search("""RELEASE[\s]*=[\s]*'?"?([0-9\.]+)'?"?""", line)
        if match is not None:
            #print(match.group(1))
            version = match.group(1)
        match = re.search("""DEV_LEVEL[\s]*=[\s]*'?"?([0-9]+)'?"?""", line)
        if match is not None:
            #print(match.group(1))
            dev_version = match.group(1)
    fobj.close()

    if version != -1 and dev_version != -1:
        return str(version + "." + dev_version)
    else:
        return ""

def check_version(version, newest_version):
    if StrictVersion(newest_version) > StrictVersion(version):
        return False
    else:
        return True

def get_newest_version():
    response = urllib.request.urlopen("http://update.joomla.org/core/list.xml")

    highest_version = "0.0"
    for line in response:
        match = re.search("""[\s]version="?'?([0-9\.]+)"?'?""", str(line))
        if match is not None:
            if StrictVersion(match.group(1)) > StrictVersion(highest_version):
                highest_version = match.group(1)

    return highest_version

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# MAIN
###########

newest_version = get_newest_version()

print(bcolors.HEADER + "Newest Joomla Version: ", bcolors.OKBLUE, newest_version, bcolors.ENDC, "\n")

fobj = open(csv_file_name, "w")
fobj.write("Status;Actual Version;Newest Version;Domain;Path\n")

for file_path in Path(base_path).glob('**/version.php'):
    newest_version = get_newest_version()
    version = get_joomla_version(str(file_path))
    domain = "unknown"

    match = re.search("""/([a-zA-Z0-9-]+\.[a-zA-Z]{2,})/""", str(file_path))
    if match is not None:
        domain = match.group(1)

    if version:
        if not check_version(version, newest_version):
            print(bcolors.FAIL, "[WARNING]", bcolors.ENDC, "Outdated Joomla version found!\t[", bcolors.FAIL + version + bcolors.ENDC, "] [", bcolors.WARNING + domain + bcolors.ENDC, "] \tin ", file_path)
            fobj.write("WARN;" + version + ";" + newest_version + ";" + domain + ";" + str(file_path) + "\n")
        else:
            print(bcolors.OKGREEN, "[OK]     ", bcolors.ENDC, "Up to date Joomla version found!\t[", bcolors.OKGREEN + version + bcolors.ENDC, "] [", bcolors.WARNING + domain + bcolors.ENDC, "] \tin ", file_path)
            fobj.write("OKOK;" + version + ";" + newest_version + ";" + domain + ";" + str(file_path) + "\n")

fobj.close()
print("\n" + bcolors.HEADER + "All versions written to: ", bcolors.OKBLUE, csv_file_name, bcolors.ENDC)
