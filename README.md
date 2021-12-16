# log4shell-detector

Detector for Log4Shell exploitation attempts

## What it does and doesn't do

It does: It checks local log files for indicators of exploitation attempts, even heavily obfuscated ones that string or regular expression based patterns wouldn't detect.

- It doesn't find vulnerable applications
- It doesn't and can't verify if the exploitation attempts were successful

## Idea

The problem with the log4j CVE-2021-44228 exploitation is that the string can be heavily obfuscated in many different ways. It is impossible to cover all possible forms with a reasonable regular expression.

The idea behind this detector is that the respective characters have to appear in a log line in a certain order to match.

```none
${jndi:ldap:
```

Split up into a list it would look like this:

```none
['$', '{', 'j', 'n', 'd', 'i', ':', 'l', 'd', 'a', 'p', ':']
```

I call these lists 'detection pads' in my script and process each log line character by character. I check if each character matches the first element of the detection pads. If the character matches a character in one of the detection pads, a pointer moves forward.

When the pointer reaches the end of the list, the detection triggered and the script prints the file name, the complete log line, the detected string and the number of the line in the file.

I've included a decoder for URL based encodings. If we need more, please let me know.

## Usage

```help
usage: log4shell-detector.py [-h] [-p path [path ...] | -f path [path ...] | --auto] [-d distance] [--quick] [--debug] [--summary]

Log4Shell Exploitation Detectors

optional arguments:
  -h, --help          show this help message and exit
  -p path [path ...]  Path to scan
  -f path [path ...]  File to scan
  --auto              Automatically evaluate locations to which logs get written and scan these folders recursively (new default if no path is given)
  -d distance         Maximum distance between each character
  -c check_usage      Check log4j usage before launching the scan
  --debug             Debug output
  --defaultpaths      Scan a set of default paths that should contain relevant log files.
  --quick             Skip log lines that don't contain a 2021 or 2022 time stamp
  --debug             Debug output
  --summary           Show summary only
  --silent            Silent Mode. Only output on matches and errors
```

## Get started

1. Make sure that the target systems on which you'd like to run `log4shell-detector` has python installed: `python -V` and see if Python 3 is available `python3 -V`

2. Download this Repo by clicking "Code" > "Download ZIP"

3. Extract the package and bring othe comlete package to the target system (e.g. with scp)

4. Run it with `python3 log4shell-detector.py -p /var/log` (if `python3` isn't available use `python`)

5. If your applications log to a different folder than `/var/log` find out where the log files reside and scan these folders. Find locations to which apps write logs with `lsof | grep '\.log'`.

6. Review the results (see FAQs for details)

## Using ansible-playbook

You can also use the `playbook.yml` which copies the needed files on the server,
runs the script and only shows something if a match was found.

Use it like this:

```bash
ansible-playbook -i hosts playbook.yml
```

which could result in something like this:

```ansible
TASK [Run the script] ******************************************************************************************************************************************************
fatal: [foo]: FAILED! => changed=false 
  <omitted>
  stdout: |-
    [!] FILE: /var/log/messages LINE_NUMBER: 6098 DEOBFUSCATED_STRING: ${jndi:ldap: LINE: ${jndi:ldap:foo
    [!] 1 files with exploitation attempts detected in PATH: /var/log/
```

## FAQs

### I don't use log4j on that server but the scanner reports exploitation attempts. Am I affected?

No. But can you be sure that no application uses log4j?

You can try to find evidence of log4j usage running these commands:

```bash
ps aux | egrep '[l]og4j'
find / -iname "log4j*"
lsof | grep log4j
find . -name '*[wj]ar' -print -exec sh -c 'jar tvf {} | grep log4j' \;
```

If none of these commands returned a result, you should be safe.

### My applications use log4j and I've found evidence of exploitation attempts? Am I compromised?

It is possible, yes. First check if the application that you use is actually affected by the vulnerability. Check the JAVA and log4j versions, check the vendor's blog for an advisory or test the application yourself using [canary tokens](https://twitter.com/cyb3rops/status/1469405846010572816).

If your application is affected and vulnerable and you plan to do a forensic investigation,

1. create a memory image of that system (use e.g. VMWare's [snapshots](https://blogs.vmware.com/networkvirtualization/2021/03/memory-forensics-for-virtualized-hosts.html/) or other tools for that)

2. create a disk image of that system

3. check the system's outgoing network connections in your firewall logs

4. check the system's crontab for suspicious new entries (`/etc/crontab`). If you want and can, use our free tool [THOR Lite](https://www.nextron-systems.com/thor-lite/) for a basic compromise assessment.

5. After some investigations, decide if you want and can disconnect that system from the Internet until you've verified that it hasn't been compromised.

## Special Flags

### --auto

Automatically select file paths to which log files get written. (default: overwrite with -p path or -f file)

### --check_usage

Check log4j usage before launching the exploits scan. The usage of this optional flag stop the execution of the script if there is no log4j being used in the current system, the thing that helps saving time especially when it's about scanning an entire infrastructure.

### --quick

Only checks log lines that contain a `2021` or `2022` to exclude all scanning of older log entries. We assume that the vulnerability wasn't exploited in 2019 and earlier.

### --summary

Prints a summary of matches, with only the filename and line number.

### --silent

Silent Mode. Only output on matches (stdout) and errors (stderr)

## Requirements

- Python 2 or Python 3

No further or special Python modules are required. It should run on any system that runs Python.

## Screenshots

![Screen1](/screenshots/screen1.png)

![Screen2](/screenshots/screen2.png)

## Help

There are different ways how you can help.

1. Test it against the payloads that you find in the wild and let me know if we miss something.
2. Help me find and fix bugs.
3. Test if the scripts runs with Python 2; if not, we can add a slightly modified version to the repo.

# Test Your Changes

Test your changes to the script with:

```bash 
pytest
```

Requires:
```bash 
pip install pytest
```

## Contact

Twitter: [@cyberops](https://twitter.com/cyb3rops)
