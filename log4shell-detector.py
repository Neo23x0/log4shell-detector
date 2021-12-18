#!/usr/bin/env python3

from __future__ import print_function

__author__ = "Florian Roth"
__version__ = "0.11.1"
__date__ = "2021-12-15"

import argparse
import os
import subprocess
import sys
from datetime import datetime, timedelta
from collections import defaultdict

import Log4ShellDetector.Log4ShellDetector as Log4ShellDetector

LINUX_PATH_SKIPS_START = set(["/proc", "/dev", "/sys/kernel/debug", "/sys/kernel/slab", "/sys/devices", "/usr/src/linux"])

def evaluate_log_paths():
    paths = []
    if not args.silent: print("[.] Automatically evaluating the folders to which apps write logs ...")
    command = "lsof 2>/dev/null | grep '\\.log' | sed 's/.* \\//\\//g' | sort | uniq"
    path_eval = subprocess.Popen(command,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    output = path_eval.communicate()[0].splitlines()
    for o in output:
        path = os.path.dirname(o)
        if isinstance(path, bytes):
            path = path.decode("utf-8")

        # Some filters
        skip_append = False
        # If already in list - skip
        if path in paths:
            skip_append = True
        # If in exclude list - skip
        for exclude in LINUX_PATH_SKIPS_START:
            if path.startswith(exclude):
                skip_append = True
        if skip_append:
            continue

        # Append the found path
        paths.append(path)
        if args.debug:
            print("[D] Adding PATH: %s" % path)
    return paths

def check_log4j_used():
    checker_commands = [
        "ps aux | egrep '[l]og4j'",
        "find / -iname \"log4j*\"",
        "lsof | grep log4j",
        "grep -r --include *.[wj]ar \"JndiLookup.class\" / 2>&1 | grep matches",
    ]
    for checker_command in checker_commands:
        if len(subprocess.Popen(checker_command,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT).communicate()[0].splitlines()) > 0:
            return True
    return False

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Log4Shell Exploitation Detectors')
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-p', nargs='+', help='Path to scan', metavar='path', default='')
    group.add_argument('-f', nargs='+', help='File to scan', metavar='path', default='')
    group.add_argument('--auto', action='store_true', help='Automatically evaluate locations to which logs get written and scan these folders recursively (new default if no path is given)')
    parser.add_argument('-d', type=int, help='Maximum distance between each character', metavar='distance', default=40)
    parser.add_argument('--quick', action='store_true', help="Skip log lines that don't contain a 2021 or 2022 time stamp")
    parser.add_argument('--debug', action='store_true', help='Debug output')
    parser.add_argument('--summary', action='store_true', help='Show summary only')
    parser.add_argument('--check_usage', '-c',action='store_true', help='Check if log4j is being used before launching the scan')
    parser.add_argument('--silent', action='store_true', help='Silent Mode. Only output on matches and errors')

    args = parser.parse_args()

    if not args.silent:
        print("     __             ____ ______       ____  ___      __          __          ")
        print("    / /  ___  ___ _/ / // __/ /  ___ / / / / _ \\___ / /____ ____/ /____  ____")
        print("   / /__/ _ \\/ _ `/_  _/\\ \\/ _ \\/ -_) / / / // / -_) __/ -_) __/ __/ _ \\/ __/")
        print("  /____/\\___/\\_, / /_//___/_//_/\\__/_/_/ /____/\\__/\\__/\\__/\\__/\\__/\\___/_/ ")
        print("            /___/                                                            ")
        print(" ")
        print("  Version %s, %s" % (__version__, __author__))

        print("")
        date_scan_start = datetime.now()
        print("[.] Starting scan DATE: %s" % date_scan_start)

    if args.check_usage:
        if check_log4j_used() == False:
            if not args.silent:
                print("[.] log4j is not being used in this system, exiting.")
            sys.exit(0)
        else:
            if not args.silent:
                print("[.] log4j is being used, an exploit's scan will be performed.")

    # Create Log4Shell Detector Object
    l4sd = Log4ShellDetector.detector(maximum_distance=args.d, debug=args.debug, quick=args.quick, silent=args.silent)

    # Counter
    all_detections = 0

    def scan_path(l4sd, path, summary):
        matches = defaultdict(lambda: defaultdict())
        # Loop over files
        for root, directories, files in os.walk(path, followlinks=False):
            for filename in files:
                file_path = os.path.join(root, filename)
                if l4sd.debug:
                    print("[.] Processing %s ..." % file_path)
                matches_found = l4sd.scan_file(file_path)
                if len(matches_found) > 0:
                    for m in matches_found:
                        matches[file_path][m['line_number']] = [m['line'], m['match_string']]

        if not summary:
            for match in matches:
                for line_number in matches[match]:
                    print('[!] FILE: %s LINE_NUMBER: %s DEOBFUSCATED_STRING: %s LINE: %s' % (match, line_number, matches[match][line_number][1], matches[match][line_number][0]))
        # Result
        number_of_detections = 0
        number_of_files_with_detections = len(matches.keys())
        for file_path in matches:
            number_of_detections += len(matches[file_path].keys())

        if number_of_detections > 0:
            print("[!] %d files with exploitation attempts detected in PATH: %s" % (number_of_files_with_detections, path))
            if summary:
                for match in matches:
                    for line_number in matches[match]:
                        print('[!] FILE: %s LINE_NUMBER: %d STRING: %s' % (match, line_number, matches[match][line_number][1]))
        else:
            if not args.silent: print("[+] No files with exploitation attempts detected in path PATH: %s" % path)
        return number_of_detections

    # Scan file
    if args.f:
        files = args.f
        for f in files:
            if not os.path.isfile(f):
                print("[E] File %s doesn't exist" % f, file=sys.stderr)
                continue
            if not args.silent: print("[.] Scanning FILE: %s ..." % f)
            matches = defaultdict(lambda: defaultdict())
            matches_found = l4sd.scan_file(f)
            if len(matches_found) > 0:
                for m in matches_found:
                    matches[f][m['line_number']] = [m['line'], m['match_string']]
                for match in matches:
                    for line_number in matches[match]:
                        print('[!] FILE: %s LINE_NUMBER: %s DEOBFUSCATED_STRING: %s LINE: %s' %
                            (match, line_number, matches[match][line_number][1], matches[match][line_number][0])
                        )
            all_detections = len(matches[f].keys())

    # Scan paths
    else:
        # Paths
        paths = args.p
        # Automatic path evaluation
        auto_eval_paths = False
        if args.auto:
            auto_eval_paths = True
        # Parameter evaluation
        if len(paths) == 0 and not auto_eval_paths:
            print("[W] Warning: You haven't selected a path (-p path) or automatic evaluation of log paths (--auto). Log4Shell-Detector will activate the automatic path evaluation (--auto) for your convenience.")
            auto_eval_paths = True
        # Automatic path evaluation
        if auto_eval_paths:
            log_paths = evaluate_log_paths()
            paths = log_paths
        # Now scan these paths
        for path in paths:
            if not os.path.isdir(path):
                print("[E] Path %s doesn't exist" % path, file=sys.stderr)
                continue
            if not args.silent: print("[.] Scanning FOLDER: %s ..." % path)
            detections = scan_path(l4sd,path,args.summary)
            all_detections += detections

    # Finish
    if not args.silent:
        if all_detections > 0:
            print("[!!!] %d exploitation attempts detected in the complete scan" % all_detections)
        else:
            print("[.] No exploitation attempts detected in the scan")
        date_scan_end = datetime.now()
        print("[.] Finished scan DATE: %s" % date_scan_end)
        duration = date_scan_end - date_scan_start
        mins, secs = divmod(duration.total_seconds(), 60)
        hours, mins = divmod(mins, 60)
        print("[.] Scan took the following time to complete DURATION: %d hours %d minutes %d seconds" % (hours, mins, secs))

