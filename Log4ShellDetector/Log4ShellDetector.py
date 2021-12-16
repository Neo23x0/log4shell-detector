
from __future__ import print_function
import base64
import re
import os
import copy
import gzip
import io
import traceback
import sys

try:
    from urllib.parse import unquote
except ImportError:
    from urllib import unquote
import traceback

_std_supported = False
try:
    import zstandard
    _std_supported = True
except ImportError:
    print("[E] No support for zstandard files without 'zstandard' library", file=sys.stderr)


class detector(object):

    # These strings will be transformed into detection pads
    DETECTION_STRINGS = ['${jndi:ldap:', '${jndi:rmi:', '${jndi:ldaps:', '${jndi:dns:', 
    '${jndi:nis:', '${jndi:nds:', '${jndi:corba:', '${jndi:iiop:']
    # These strings will be applied as they are
    PLAIN_STRINGS = {
        "https://gist.github.com/Neo23x0/e4c8b03ff8cdf1fa63b7d15db6e3860b#gistcomment-3991502": [
            " header with value of BadAttributeValueException: "
        ],
        "https://gist.github.com/Neo23x0/e4c8b03ff8cdf1fa63b7d15db6e3860b#gistcomment-3991700": [
            "at java.naming/com.sun.jndi.url.ldap.ldapURLContext.lookup(", 
            ".log4j.core.lookup.JndiLookup.lookup(JndiLookup"
        ],
        "https://github.com/tangxiaofeng7/CVE-2021-44228-Apache-Log4j-Rce/issues/1": [
            'Reference Class Name: foo'
        ]
    }

    def __init__(self, maximum_distance, debug, quick, silent):
        self.prepare_detections(maximum_distance)
        self.debug = debug
        self.quick = quick
        self.silent = silent

    def decode_line(self, line):
        while "%" in line:
            line_before = line
            line = unquote(line)
            if line == line_before:
                break
        return line

    def base64_decode(self, m):
        return base64.b64decode(m.group(1)).decode("utf-8")

    def check_line(self, line):
        # Decode Line
        decoded_line = self.decode_line(line)

        # Base64 sub
        try:
            decoded_line = re.sub(r"\${base64:([^}]+)}", self.base64_decode, decoded_line)
        except Exception as e:
            if args.debug:
                traceback.print_exc()

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
                    # { directly follows $
                    if dp[detection_string]["level"] == 1 and not dp[detection_string]["current_distance"] == 1:
                        # if not ${ but $ .... { do a complete reset of the pad evaluation
                        dp[detection_string]["current_distance"] = 0
                        dp[detection_string]["level"] = 0 
                    dp[detection_string]["level"] += 1
                    dp[detection_string]["current_distance"] = 0
                # If level > 0 count distance to the last char
                if dp[detection_string]["level"] > 0:
                    dp[detection_string]["current_distance"] += 1
                    # If distance is too big, reset level to zero
                    if dp[detection_string]["current_distance"] > dp[detection_string]["maximum_distance"]:
                        dp[detection_string]["current_distance"] = 0
                        dp[detection_string]["level"] = 0 
                # Is the pad complete
                if len(dp[detection_string]["chars"]) == dp[detection_string]["level"]:
                    return detection_string

    def scan_file(self, file_path):
        matches_in_file = []
        try:
            # Gzipped logs
            if "log" in file_path and file_path.endswith(".gz"):
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
            # Zstandard logs
            elif _std_supported and "log." in file_path and file_path.endswith(".zst"):
                with open(file_path, 'rb') as compressed:
                    dctx = zstandard.ZstdDecompressor()
                    stream_reader = dctx.stream_reader(compressed)
                    text_stream = io.TextIOWrapper(stream_reader, encoding='utf-8')
                    c = 0
                    for line in text_stream:
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
            elif self.is_ascii(file_path):
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
                print("[E] Can't process FILE: %s REASON: most likely not an ASCII based log file" % file_path, file=sys.stderr)
        except PermissionError as e:
            print("[E] Can't access %s due to a permission problem." % file_path, file=sys.stderr)
        except Exception as e:
            print("[E] Can't process FILE: %s REASON: %s" % (file_path, traceback.print_exc()), file=sys.stderr)

        return matches_in_file

    def is_ascii(self, file_path):
        with open(file_path, "r") as fh:
            first_2048_bytes = fh.read(2048)
            if all(ord(c) < 128 for c in first_2048_bytes):
                return True 
        return False

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
