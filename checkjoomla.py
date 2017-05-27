#!/usr/bin/env python3

import argparse
import hashlib
import os
import os.path
import re
import shutil
import stat
import sys
import socket
import urllib.request
import urllib.error
import zipfile
from distutils.version import StrictVersion
from pathlib import Path

##############################################################
# CONFIG
##############################################################

# BASE BASE
base_path = '/var/www/vhosts'

# CSV FILENAME
csv_file_name = 'joomla_status.csv'

# TMP DOWNLOAD DIR
tmp_dl_dir = '/tmp'


#############################################################

def get_joomla_version(version_file_path):
    version_file = open(version_file_path, "r", -1, None, 'replace')
    main_version = -1
    dev_version = -1
    for line in version_file:
        if main_version != -1 and dev_version != -1:
            break

        version_match = re.search("""RELEASE[\s]*=[\s]*'?"?([0-9.]+)'?"?""", line)
        if version_match is not None:
            # print(version_match.group(1))
            main_version = version_match.group(1)

        version_match = re.search("""DEV_LEVEL[\s]*=[\s]*'?"?([0-9]+)'?"?""", line)
        if version_match is not None:
            # print(version_match.group(1))
            dev_version = version_match.group(1)
    version_file.close()

    if main_version != -1 and dev_version != -1:
        return str(main_version + "." + dev_version)
    else:
        return ""


def check_version(current_version, latest_version):
    if StrictVersion(latest_version) > StrictVersion(current_version):
        return False
    else:
        return True


def get_newest_version():
    response = urllib.request.urlopen("http://update.joomla.org/core/list.xml")

    highest_version = "0.0"
    for line in response:
        version_match = re.search("""[\s]version="?'?([0-9.]+)"?'?""", str(line))
        if version_match is not None:
            if StrictVersion(version_match.group(1)) > StrictVersion(highest_version):
                highest_version = version_match.group(1)

    return highest_version


def download_joomla_version(joomla_version):
    version_match = re.search("""(\d+)\.(\d+)(\.(\d+))?([ab](\d+))?""", joomla_version)

    dst_path = ""
    if version_match is not None:
        if version_match.group(1) == "2":
            version_path = "joomla25"
        else:
            version_path = "joomla3"
        version_string = version_match.group(1) + "-" + version_match.group(2) + "-" + version_match.group(4)

        # check if file has already been downloaded...
        dst_path = tmp_dl_dir + "/orig_joomla_" + joomla_version + ".zip"
        dst_file = Path(dst_path)
        if not dst_file.is_file():
            if StrictVersion(joomla_version) > StrictVersion('3.7.1'):
                version_string2 = ".".join(version_string.rsplit('-', 1))

                url = "https://downloads.joomla.org/cms/" + \
                      version_path + "/" + version_string + \
                      "/Joomla_" + version_string2 + \
                      "-Stable-Full_Package.zip?format=zip"
            else:
                url = "https://downloads.joomla.org/cms/" + \
                      version_path + "/" + version_string + \
                      "/joomla_" + version_string + \
                      "-stable-full_package-zip?format=zip"

            try:
                urllib.request.urlretrieve(url, dst_path)
            except (urllib.error.URLError, urllib.error.HTTPError, socket.error):
                # print("Download of", url, "failed!")
                dst_path = ""

    return dst_path


def extract_downloaded_joomla_version(joomla_version, zip_file_path):
    dst_path = tmp_dl_dir + "/orig_joomla_" + joomla_version

    # extract a fresh copy...
    shutil.rmtree(dst_path, onerror=remove_readonly)

    try:
        with zipfile.ZipFile(zip_file_path, "r") as zip_ref:
            zip_ref.extractall(dst_path)
    except (urllib.error.URLError, urllib.error.HTTPError, socket.error):
        dst_path = ""

    return dst_path


def remove_readonly(func, path, excinfo):
    if os.path.isdir(path):
        os.chmod(path, stat.S_IWRITE)
        func(path)


def get_dir_md5(dir_root):
    exclude_dirs = {"installation", "tmp"}

    md5_hash = hashlib.md5()
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
                md5_hash.update(chunk)

    return md5_hash.hexdigest()


def cmp_joomla_directories(original_root, installation_root):
    exclude_dirs = {"installation", "tmp", "logs"}

    check_failures = []

    for dir_path, dir_names, file_names in os.walk(original_root, topdown=True):

        dir_names.sort(key=os.path.normcase)
        file_names.sort(key=os.path.normcase)

        dir_names[:] = [d for d in dir_names if d not in exclude_dirs]

        for filename in file_names:
            relative_path = os.path.relpath(dir_path, original_root)

            if relative_path == ".":
                relative_path = ""

            orig_file_path = os.path.join(dir_path, filename)
            inst_file_path = os.path.join(installation_root, os.path.join(relative_path, filename))

            if os.path.isfile(inst_file_path):
                hash_orig = hashlib.md5()
                f = open(orig_file_path, 'rb')
                for chunk in iter(lambda: f.read(65536), b''):
                    hash_orig.update(chunk)
                f.close()

                hash_inst = hashlib.md5()
                f = open(inst_file_path, 'rb')
                for chunk in iter(lambda: f.read(65536), b''):
                    hash_inst.update(chunk)
                f.close()

                if hash_orig.hexdigest() == hash_inst.hexdigest():
                    """
                    print("file ok", 
                          os.path.join(relative_path, filename), 
                          hash_orig.hexdigest(), 
                          hash_inst.hexdigest())
                    """
                    pass
                else:
                    """
                    print("file NOT OK!", 
                          os.path.join(relative_path, filename), 
                          hash_orig.hexdigest(), 
                          hash_inst.hexdigest())
                    """
                    check_failures.append(os.path.join(relative_path, filename))
            else:
                # print("File", os.path.join(relative_path, filename), "is missing!")
                pass

    return check_failures


class ConsoleColors:
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

print(ConsoleColors.HEADER + "Newest Joomla Version: ", ConsoleColors.OKBLUE, newest_version, ConsoleColors.ENDC, "\n")

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
            print(ConsoleColors.FAIL, "[WARNING]", ConsoleColors.ENDC, "Outdated Joomla version found!\t[",
                  ConsoleColors.FAIL + version + ConsoleColors.ENDC, "] [",
                  ConsoleColors.WARNING + domain + ConsoleColors.ENDC, "] \tin ",
                  file_path)
            version_status = "WARN"
        else:
            print(ConsoleColors.OKGREEN, "[OK]     ", ConsoleColors.ENDC, "Up to date Joomla version found!\t[",
                  ConsoleColors.OKGREEN + version + ConsoleColors.ENDC, "] [",
                  ConsoleColors.WARNING + domain + ConsoleColors.ENDC, "] \tin ",
                  file_path)
            version_status = "OKOK"

        if not args.nointegrity:
            print(ConsoleColors.HEADER, " -> Checking file integrity: ", ConsoleColors.ENDC, end=" ")
            sys.stdout.flush()
            dl_path = download_joomla_version(version)

            if not dl_path:
                print(ConsoleColors.FAIL, "Failed to download joomla source!", ConsoleColors.ENDC)
            else:
                orig_root = extract_downloaded_joomla_version(version, dl_path)
                cms_root = os.path.dirname(os.path.dirname(os.path.dirname(
                    os.path.dirname(str(file_path)))))  # strip "libraries/cms/version/version.php" from filename

                if not orig_root:
                    print(ConsoleColors.FAIL, "Failed to extract joomla source!", ConsoleColors.ENDC)
                else:
                    result_list = cmp_joomla_directories(orig_root, cms_root)

                    if len(result_list) == 0:
                        print(ConsoleColors.OKGREEN, "OK", ConsoleColors.ENDC)
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
                            print(ConsoleColors.WARNING, "OK", ConsoleColors.ENDC, "Use -v to get details!")
                            integrity_status = "WARN"
                        else:
                            print(ConsoleColors.FAIL, "FAIL", ConsoleColors.ENDC, "Use -v to get details!")
                            integrity_status = "FAIL"

                    if args.verbose:
                        if len(result_list) > 0:
                            print('\tMissmatch: %s' % '\n\tMissmatch: '.join(map(str, result_list)))

        fobj.write(
            version_status + ";" + integrity_status + ";" + version + ";" + newest_version + ";" + domain + ";" + str(
                file_path) + "\n")
        print("")  # empty last line

fobj.close()
print("\n" + ConsoleColors.HEADER + "All versions written to: ",
      ConsoleColors.OKBLUE, csv_file_name, ConsoleColors.ENDC)
