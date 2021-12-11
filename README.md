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

I call these lists 'detection pads' in my script and process each log line character by character. I check if each character matches the first element of the detection pads. If the character matches the first character in one of the detection pads, it gets removed. 

When all characters of a pad have been removed, the detection triggered and the script prints the file name, the complete log line, the detected string and the number of the line in the file.

I've included a decoder for URL based encodings. If we need more, please let me know. 

## Usage

```bash
usage: log4shell-detector.py [-h] [-p path] [--debug]

Log4Shell Exploitation Detectors

optional arguments:
  -h, --help  show this help message and exit
  -p path     Path to scan
  --debug     Debug output
```

## Requirements 

- Python3

No further or special Python modules are required. It should run on any system that runs Python3.

## Screenshots

![Screen1](/screenshots/screen1.png)

![Screen2](/screenshots/screen2.png)
