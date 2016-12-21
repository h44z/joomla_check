#!/usr/bin/env python3

from pathlib import Path
import re
import urllib.request
from urllib.request import urlretrieve
import zipfile
import shutil
import stat
import os
import os.path
import hashlib
import sys
import argparse
from distutils.version import StrictVersion

##############################################################
## CONFIG
##############################################################

# BASE BASE
base_path = '/var/www/vhosts'

# CSV FILENAME
csv_file_name = 'joomla_status.csv'

# TMP DOWNLOAD DIR
tmp_dl_dir = '/tmp'

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

def download_joomla_version(version):
    version_match = re.search("""(\d+)\.(\d+)(\.(\d+))?([ab](\d+))?""", version)
    
    dst_path = ""
    if version_match is not None:
        if version_match.group(1) == "2":
            version_path = "joomla25"
        else:
            version_path = "joomla3"
        version_string = version_match.group(1) + "-" + version_match.group(2) + "-" + version_match.group(4)

        # check if file has already been downloaded...
        dst_path = tmp_dl_dir + "/orig_joomla_" + version + ".zip"
        dst_file = Path(dst_path)
        if not dst_file.is_file():
            url = "https://downloads.joomla.org/cms/" + version_path + "/" + version_string + "/joomla_" + version_string + "-stable-full_package-zip?format=zip"
            try:
                urllib.request.urlretrieve (url, dst_path)
            except:
                dst_path = ""

    return dst_path

def extract_downloaded_joomla_version(version, path):
    dst_path = tmp_dl_dir + "/orig_joomla_" + version

    # extract a fresh copy...
    shutil.rmtree(dst_path, onerror=remove_readonly)

    try:
        with zipfile.ZipFile(path, "r") as zip_ref:
            zip_ref.extractall(dst_path)
    except:
        dst_path = ""

    return dst_path

def remove_readonly(func, path, excinfo):
    if os.path.isdir(path):
        os.chmod(path, stat.S_IWRITE)
        func(path)

def get_dir_md5(dir_root):
    exclude_dirs = {"installation", "tmp"}

    hash = hashlib.md5()
    for dirpath, dirnames, filenames in os.walk(dir_root, topdown=True):

        dirnames.sort(key=os.path.normcase)
        filenames.sort(key=os.path.normcase)

        dirnames[:] = [d for d in dirnames if d not in exclude_dirs]

        for filename in filenames:
            filepath = os.path.join(dirpath, filename)

            # If some metadata is required, add it to the checksum

            # 1) filename (good idea)
            # hash.update(os.path.normcase(os.path.relpath(filepath, dir_root))

            # 2) mtime (possibly a bad idea)
            # st = os.stat(filepath)
            # hash.update(struct.pack('d', st.st_mtime))

            # 3) size (good idea perhaps)
            # hash.update(bytes(st.st_size))

            f = open(filepath, 'rb')
            for chunk in iter(lambda: f.read(65536), b''):
                hash.update(chunk)

    return hash.hexdigest()

def cmp_joomla_directories(original_root, installation_root):
    exclude_dirs = {"installation", "tmp", "logs"}

    check_failures = []    
    
    for dirpath, dirnames, filenames in os.walk(original_root, topdown=True):

        dirnames.sort(key=os.path.normcase)
        filenames.sort(key=os.path.normcase)

        dirnames[:] = [d for d in dirnames if d not in exclude_dirs]

        for filename in filenames:
            relative_path = os.path.relpath(dirpath, original_root)

            if relative_path == ".":
                relative_path = ""

            orig_filepath = os.path.join(dirpath, filename)
            inst_filepath = os.path.join(installation_root, os.path.join(relative_path, filename))
            
            if os.path.isfile(inst_filepath):
                hash_orig = hashlib.md5()
                f = open(orig_filepath, 'rb')
                for chunk in iter(lambda: f.read(65536), b''):
                    hash_orig.update(chunk)
                f.close()
            
                hash_inst = hashlib.md5()
                f = open(inst_filepath, 'rb')
                for chunk in iter(lambda: f.read(65536), b''):
                    hash_inst.update(chunk)
                f.close()

                if hash_orig.hexdigest() == hash_inst.hexdigest():
                    #print("file ok", os.path.join(relative_path, filename), hash_orig.hexdigest(), hash_inst.hexdigest())
                    pass
                else:
                    #print("file NOT OK!!!!!!!!!!!!!!!!!!!!!!!", os.path.join(relative_path, filename), hash_orig.hexdigest(), hash_inst.hexdigest())
                    check_failures.append(os.path.join(relative_path, filename))
            else:
                #print("File", os.path.join(relative_path, filename), "is missing!")
                pass

    return check_failures

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

parser = argparse.ArgumentParser(description='Check joomla installation state.')
parser.add_argument('-v', '--verbose', action='store_true', help='Print verbose output')
parser.add_argument('-n', '--nointegrity', action='store_true', help='Skip integrity check')

args = parser.parse_args()

newest_version = get_newest_version()

print(bcolors.HEADER + "Newest Joomla Version: ", bcolors.OKBLUE, newest_version, bcolors.ENDC, "\n")

fobj = open(csv_file_name, "w")
fobj.write("Status;Integrity;Actual Version;Newest Version;Domain;Path\n")

for file_path in Path(base_path).glob('**/version.php'):
    newest_version = get_newest_version()
    version = get_joomla_version(str(file_path))
    domain = "unknown"

    match = re.search("""/([a-zA-Z0-9-]+\.[a-zA-Z]{2,})/""", str(file_path))
    if match is not None:
        domain = match.group(1)

    if version:
        version_status = "UNKN"
        integrity_status = "UNKN"
        if not check_version(version, newest_version):
            print(bcolors.FAIL, "[WARNING]", bcolors.ENDC, "Outdated Joomla version found!\t[", bcolors.FAIL + version + bcolors.ENDC, "] [", bcolors.WARNING + domain + bcolors.ENDC, "] \tin ", file_path)
            version_status = "WARN"
        else:
            print(bcolors.OKGREEN, "[OK]     ", bcolors.ENDC, "Up to date Joomla version found!\t[", bcolors.OKGREEN + version + bcolors.ENDC, "] [", bcolors.WARNING + domain + bcolors.ENDC, "] \tin ", file_path)
            version_status = "OKOK"

        if not args.nointegrity:
            print(bcolors.HEADER, " -> Checking file integrity: ", bcolors.ENDC, end=" ")
            sys.stdout.flush()
            dl_path = download_joomla_version(version)

            if not dl_path:
                print(bcolors.FAIL, "Failed to download joomla source!", bcolors.ENDC)
            else:
                orig_root = extract_downloaded_joomla_version(version, dl_path)
                cms_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(str(file_path))))) # strip "libraries/cms/version/version.php" from filename

                if not orig_root:
                    print(bcolors.FAIL, "Failed to extract joomla source!", bcolors.ENDC)
                else:
                    result_list = cmp_joomla_directories(orig_root, cms_root)

                    if len(result_list) == 0:
                        print(bcolors.OKGREEN, "OK", bcolors.ENDC)
                        integrity_status = "OKOK"
                    else:
                        # check if only image files differ... if so ignore it.
                        real_fail_count = 0

                        for fail_path in result_list:
                            if fail_path.lower().endswith(".jpg") or fail_path.lower().endswith(".png"):
                                pass
                            else:
                                real_fail_count = real_fail_count + 1

                        if real_fail_count == 0:
                            print(bcolors.WARNING, "OK", bcolors.ENDC, "Use -v to get details!")
                            integrity_status = "WARN"
                        else:
                            print(bcolors.FAIL, "FAIL", bcolors.ENDC, "Use -v to get details!")
                            integrity_status = "FAIL"
                    
                    if args.verbose:
                        if len(result_list) > 0:
                            print('\tMissmatch: %s' % '\n\tMissmatch: '.join(map(str, result_list)))
        
        fobj.write(version_status + ";" + integrity_status + ";" + version + ";" + newest_version + ";" + domain + ";" + str(file_path) + "\n")
        print("") # empty last line

fobj.close()
print("\n" + bcolors.HEADER + "All versions written to: ", bcolors.OKBLUE, csv_file_name, bcolors.ENDC)
