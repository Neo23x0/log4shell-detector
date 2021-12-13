#!/usr/bin/env python3

__author__ = "Florian Roth"
__version__ = "0.7"
__date__ = "2021-12-13"

import os
import sys
import copy
import gzip
py3 = True if sys.version_info > (3, 0) else False
if py3:
    import urllib.parse
else:
    import urlparse
import argparse
from datetime import datetime, timedelta
import traceback

DEFAULT_PATHS = ['/var/log', '/storage/log/vmware', '/var/atlassian/application-data/jira/log']


class Log4ShellDetector(object):

    # These strings will be transformed into detection pads
    DETECTION_STRINGS = ['${jndi:ldap:', '${jndi:rmi:/', '${jndi:ldaps:/', '${jndi:dns:/', '${jndi:nis:/', '${jndi:nds:/', '${jndi:corba:/', '${jndi:iiop:/']
    # These strings will be applied as they are
    PLAIN_STRINGS = {
        "https://gist.github.com/Neo23x0/e4c8b03ff8cdf1fa63b7d15db6e3860b#gistcomment-3991502": [
            " header with value of BadAttributeValueException: "
        ],
        "https://gist.github.com/Neo23x0/e4c8b03ff8cdf1fa63b7d15db6e3860b#gistcomment-3991700": [
            "at java.naming/com.sun.jndi.url.ldap.ldapURLContext.lookup(", 
            ".log4j.core.lookup.JndiLookup.lookup(JndiLookup"
        ],
        "https://github.com/Neo23x0/log4shell-detector/issues/5#issuecomment-991963675": [
            '${base64:JHtqbmRp'
        ], 
        "https://github.com/tangxiaofeng7/CVE-2021-44228-Apache-Log4j-Rce/issues/1": [
            'Reference Class Name: foo'
        ]
    }

    def __init__(self, maximum_distance, debug, quick):
        self.prepare_detections(maximum_distance)
        self.debug = debug
        self.quick = quick

    def decode_line(self, line):
        while "%" in line:
            line_before = line
            if py3:
                line = urllib.parse.unquote(line)
            else:
                line = urlparse.unquote(line)
            if line == line_before:
                break
        return line

    def check_line(self, line):
        # Decode Line
        decoded_line = self.decode_line(line)

        # Plain Detection
        for ref, strings in self.PLAIN_STRINGS.items():
            for s in strings:
                if s in line or s in decoded_line:
                    return s

        # Detection Pad based Detection
        # Preparation
        decoded_line = decoded_line.lower()
        linechars = list(decoded_line)
        # temporary detection pad
        dp = copy.deepcopy(self.detection_pad)
        # Walk over characters
        for c in linechars:
            for detection_string in dp:
                # If the character in the line matches the character in the detection
                if c == dp[detection_string]["chars"][dp[detection_string]["level"]]:
                    dp[detection_string]["level"] += 1
                    dp[detection_string]["current_distance"] = 0
                # If level > 0 count distance to the last char
                if dp[detection_string]["level"] > 0:
                    dp[detection_string]["current_distance"] += 1
                    # If distance is too big, reset level to zero
                    if dp[detection_string]["current_distance"] > dp[detection_string]["maximum_distance"]:
                        dp[detection_string]["current_distance"] = 0
                        dp[detection_string]["level"] = 0 
                # Is the pad completely empty?
                if len(dp[detection_string]["chars"]) == dp[detection_string]["level"]:
                    return detection_string

    def scan_file(self, file_path):
        matches_in_file = []
        try:
            # Gzipped logs
            if file_path.endswith(".log.gz"):
                with gzip.open(file_path, 'rt') as gzlog:        
                    c = 0
                    for line in gzlog: 
                        c += 1
                        # Quick mode - timestamp check
                        if self.quick and not "2021" in line and not "2022" in line:
                            continue 
                        # Analyze the line  
                        result = self.check_line(line)
                        if result:
                            matches_dict = {
                                "line_number": c,
                                "match_string": result,
                                "line": line.rstrip()
                            }
                            matches_in_file.append(matches_dict)
            # Plain Text
            else:
                with open(file_path, 'r') as logfile:
                    c = 0
                    for line in logfile:
                        c += 1
                        # Quick mode - timestamp check
                        if self.quick and not "2021" in line and not "2022" in line:
                            continue
                        # Analyze the line
                        result = self.check_line(line)
                        if result:
                            matches_dict = {
                                "line_number": c,
                                "match_string": result,
                                "line": line.rstrip()
                            }
                            matches_in_file.append(matches_dict)
        except UnicodeDecodeError as e:
            if self.debug:
                print("[E] Can't process FILE: %s REASON: most likely not an ASCII based log file" % file_path)
        except Exception as e:
            print("[E] Cant proces FILE: %s REASON: %s" % (file_path, traceback.print_exc()))

        return matches_in_file

    def scan_path(self, path):
        number_of_detections = 0
        number_of_file_with_detections = 0
        # Loop over files
        for root, directories, files in os.walk(path, followlinks=False):
            for filename in files:
                file_path = os.path.join(root, filename)
                if self.debug:
                    print("[.] Processing %s ..." % file_path)
                matches_found = self.scan_file(file_path)
                if len(matches_found) > 0:
                    for m in matches_found:
                        print("[!!!] Exploitation attempt detected FILE: %s LINE_NUMBER: %d LINE: %s DEOBFUSCATED_STRING: %s" % 
                            (file_path, m["line_number"], m["line"], m["match_string"]))
                        number_of_detections += 1
                    number_of_file_with_detections += 1

        # Result
        if number_of_detections > 0:
            print("[!] %d files with exploitation attempts detected in PATH: %s" % (number_of_file_with_detections, path))
        else:
            print("[+] No files with exploitation attempts detected in path PATH: %s" % path)
        return number_of_detections

    def prepare_detections(self, maximum_distance):
        self.detection_pad = {}
        for ds in self.DETECTION_STRINGS:
            self.detection_pad[ds] = {}
            self.detection_pad[ds] = {
                "chars": list(ds),
                "maximum_distance": maximum_distance,
                "current_distance": 0,
                "level": 0
            }

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Log4Shell Exploitation Detectors')
    parser.add_argument('-p', nargs='+', help='Path to scan', metavar='path', default='')
    parser.add_argument('-f', nargs='+', help='File to scan', metavar='path', default='')
    parser.add_argument('-d', help='Maximum distance between each character', metavar='distance', default=30)
    parser.add_argument('--quick', action='store_true', default=False, help="Skip log lines that don't contain a 2021 or 2022 time stamp")
    parser.add_argument('--defaultpaths', action='store_true', default=False, help='Scan a set of default paths that should contain relevant log files.')
    parser.add_argument('--debug', action='store_true', default=False, help='Debug output')

    args = parser.parse_args()
    
    print("     __             ____ ______       ____  ___      __          __          ")
    print("    / /  ___  ___ _/ / // __/ /  ___ / / / / _ \\___ / /____ ____/ /____  ____")
    print("   / /__/ _ \\/ _ `/_  _/\\ \\/ _ \\/ -_) / / / // / -_) __/ -_) __/ __/ _ \\/ __/")
    print("  /____/\\___/\\_, / /_//___/_//_/\\__/_/_/ /____/\\__/\\__/\\__/\\__/\\__/\\___/_/ ")  
    print("            /___/                                                            ")
    print(" ")
    print("  Version %s, %s" % (__version__, __author__))
    
    if not args.p and not args.defaultpaths and not args.f:
        parser.print_help(sys.stderr)
        print("")
        print("[E] You have to select at least one folder to scan with -p target-folder, a file with -f file or use --defaultpaths")
        sys.exit(1)
    
    print("")
    date_scan_start = datetime.now()
    print("[.] Starting scan DATE: %s" % date_scan_start)
    
    # Create Log4Shell Detector Object
    l4sd = Log4ShellDetector(maximum_distance=args.d, debug=args.debug, quick=args.quick)
    
    # Counter
    all_detections = 0
    
    # Scan file
    if args.f:
        files = args.f 
        for f in files:
            if not os.path.isfile(f):
                print("[E] File %s doesn't exist" % f)
                continue
            print("[+] Scanning FILE: %s ..." % f)
            matches_found = l4sd.scan_file(f)
            if len(matches_found) > 0:
                for m in matches_found:
                    print("[!!!] Exploitation attempt detected FILE: %s LINE_NUMBER: %d LINE: %s DEOBFUSCATED_STRING: %s" % 
                        (f, m["line_number"], m["line"], m["match_string"]))
                    all_detections += 1
    # Scan paths
    else:
        paths = args.p
        if args.defaultpaths:
            paths = DEFAULT_PATHS
        for path in paths:
            if not os.path.isdir(path):
                if not args.defaultpaths:
                    print("[E] Path %s doesn't exist" % path)
                continue
            print("[+] Scanning FOLDER: %s ..." % path)
            detections = l4sd.scan_path(path)
            all_detections += detections

    # Finish
    if all_detections > 0:
        print("[!!!] %d exploitation attempts detected in the complete scan" % all_detections)
    else:
        print("[.] No exploitation attempts detected in the scan")
    date_scan_end = datetime.now()
    print("[.] Finished scan DATE: %s" % date_scan_end)
    duration = date_scan_end - date_scan_start
    mins, secs = divmod(duration.total_seconds(), 60)
    hours, mins = divmod(mins, 60)
    print("[.] Scan took the followwing time to complete DURATION: %d hours %d minutes %d seconds" % (hours, mins, secs))
