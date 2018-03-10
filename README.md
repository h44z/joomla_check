### Joomla integrity and version check script

This script is useful to check joomla versions on a webserver. It does also check integrity of joomla core files!
All outputs are written to a csv file for better automation.

#### Usage

```
checkjoomla.py [-h] [-v] [-n]
```

optional arguments:
 - -h, --help:         show this help message and exit
 - -v, --verbose:      Print verbose output
 - -n, --nointegrity:  Skip integrity check


#### Configuration

Make sure to set the variable ```base_path``` to your base webroot directory. In case you are using plesk it might be ```/var/www/vhosts```.  
Also mare sure to configure the other options in the CONFIG section of the script.