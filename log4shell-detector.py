#!/usr/bin/env python3

__author__ = "Florian Roth"
__version__ = "0.2"
__date__ = "2021-12-11"

import os
import sys
import copy
import urllib.parse
import argparse
from datetime import datetime
import traceback

DETECTION_STRINGS = ['${jndi:ldap:', '${jndi:rmi:/', '${jndi:ldaps:/', '${jndi:ldaps:/']
DEFAULT_PATHS = ['/var/log', '/storage/log/vmware']

def check_line(line, detection_pad):
    line = urllib.parse.unquote(line)
    linechars = list(line)
    # temporary detection pad
    dp = detection_pad
    # Walk over characters
    for c in linechars:
        for detection_string in dp:
            if c == dp[detection_string][0]:
                del dp[detection_string][0]
            # Is the pad completely empty?
            if len(dp[detection_string]) == 0:
                return detection_string

def scan_path(path, detection_pad, debug):
    number_of_detections = 0
    # Loop over files
    for root, directories, files in os.walk(path, followlinks=False):
        for filename in files:
            file_path = os.path.join(root, filename)
            if debug:
                print("[.] Processing %s ..." % file_path)
            try:
                with open(file_path, 'r') as logfile:
                    c = 0
                    for line in logfile:
                        c += 1
                        result = check_line(line.lower(), copy.deepcopy(detection_pad))
                        if result:
                            number_of_detections += 1
                            print("[!!!] Exploitation attempt detected FILE: %s LINE_NUMBER: %d LINE: %s DEOBFUSCATED_STRING: %s" % 
                            (file_path, c, line, result))
            except UnicodeDecodeError as e:
                if args.debug:
                    print("[E] Can't process FILE: %s REASON: most likely not an ASCII based log file" % file_path)
            except Exception as e:
                print("[E] Cant proces FILE: %s REASON: %s" % (file_path, traceback.print_exc()))
    # Result
    if number_of_detections > 0:
        print("[!] %d exploitation attempts detected in PATH: %s" % (number_of_detections, path))
    else:
        print("[+] No Log4Shell exploitation attempts detected in path PATH: %s" % path)
    return number_of_detections

def prepare_detections():
    detection_pad = {}
    for d in DETECTION_STRINGS:
        detection_pad[d] = list(d)
    return detection_pad

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Log4Shell Exploitation Detectors')
    parser.add_argument('-p', nargs='+', help='Path to scan', metavar='path', default='')
    parser.add_argument('--defaultpaths', action='store_true', default=False, help='Scan a set of default paths that should contain relevant log files.')
    parser.add_argument('--debug', action='store_true', default=False, help='Debug output')

    args = parser.parse_args()
    
    print("     __             ____ ______       ____  ___      __          __          ")
    print("    / /  ___  ___ _/ / // __/ /  ___ / / / / _ \\___ / /____ ____/ /____  ____")
    print("   / /__/ _ \/ _ `/_  _/\ \/ _ \/ -_) / / / // / -_) __/ -_) __/ __/ _ \/ __/")
    print("  /____/\\___/\\_, / /_//___/_//_/\\__/_/_/ /____/\\__/\\__/\\__/\\__/\\__/\\___/_/ ")  
    print("            /___/                                                            ")
    print(" ")
    print("  Version %s, %s" % (__version__, __author__))
    
    if not args.p and not args.defaultpaths:
        parser.print_help(sys.stderr)
        print("")
        print("[E] You have to select at least one folder to scan with -p target-folder or use --defaultpaths")
        sys.exit(1)
    
    print("")
    dateTimeObj = datetime.now()
    print("[.] Starting scan DATE: %s" % dateTimeObj)
    print("[+] Scanning FOLDER: %s ..." % args.p)
    
    # Prepare the detection pads
    detection_pad = prepare_detections()
    
    # Counter
    all_detections = 0
    
    # Scan paths
    paths = args.p
    if args.defaultpaths:
        paths = DEFAULT_PATHS
    for path in paths:
        detections = scan_path(path, detection_pad, args.debug)
        all_detections += detections

    # Finish
    if all_detections > 0:
        print("[!!!] %d exploitation attempts detected in the complete scan" % all_detections)
    else:
        print("[.] No exploitation attempts detected in the scan")
    dateTimeObj = datetime.now()
    print("[.] Finished scan DATE: %s" % dateTimeObj)