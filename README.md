# log4shell-detector

Detector for Log4Shell exploitation attempts

## Idea

The problem with the log4j CVE-2021-44228 exploitation is that the string can be heavily obfuscated in many different ways. It is impossible to cover all possible forms with a reasonable regular expression. 

The idea behind this detector is that the respective characters have to appear in a log line in a certain order to match. 

```
${jndi:ldap:
```

Split up into a list it would look like this:
```
['$', '{', 'j', 'n', 'd', 'i', ':', 'l', 'd', 'a', 'p', ':']
```

I call these lists 'detection pads' in my script and process each log line character by character. I check if each character matches the first element of the detection pads. If the character matches a character in one of the detection pads, a pointer moves forward. 

When the pointer reaches the end of the list, the detection triggered and the script prints the file name, the complete log line, the detected string and the number of the line in the file.

I've included a decoder for URL based encodings. If we need more, please let me know. 

## Usage

```help
usage: log4shell-detector.py [-h] [-p path [path ...]] [-d maxdis] [--quick] [--defaultpaths] [--debug]

Log4Shell Exploitation Detectors

optional arguments:
  -h, --help          show this help message and exit
  -p path [path ...]  Path to scan
  -d distance         Maximum distance between each character
  --quick             Skip log lines that don't contain a 2021 or 2022 time stamp
  --defaultpaths      Scan a set of default paths that should contain relevant log files.
  --debug             Debug output
```

## Special Flags

### --quick 

Only checks log lines that contain a `2021` or `2022` to exclude all scanning of older log entries. We assume that the vulnerability wasn't exploited in 2019 and earlier. 

### --defaultpaths

Check a list of default log paths used by different software products. 

## Requirements 

- Python3

No further or special Python modules are required. It should run on any system that runs Python3.

## Screenshots

![Screen1](/screenshots/screen1.png)

![Screen2](/screenshots/screen2.png)

## Help 

There are different ways how you can help.

A. Test it against the payloads that you find in-the-wild and let me know if we miss something
B. Help me find and fix bugs
C. Test if the scripts runs with Python 2; if not, we can add a slightly modified version to the repo

## Contact

Twitter: [@cyberops](https://twitter.com/cyb3rops)
