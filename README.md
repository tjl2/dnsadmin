dnsadmin
========

dnsadmin is a command line script used to create and manipulate BIND zones
and configuration files.

It needs to be installed on all nameservers in a nameserver cluster, which all
need to have SSH running.

Installation
============
Clone the repo, then do the following:
 - copy `dnsadmin.conf` and `recordtemplates.py` to `/etc/dnsadmin/`
 - copy `dnsadmin` to `/usr/local/bin` and make sure it is executable
 - copy `zone.py` to your Python lib dir (`/usr/lib/python2.4/site-packages/`
   on a RHEL/CentOS 5 system)
 - create a symlink in your Python lib dir back to `/etc/dnsadmin/recordtemplates.py`
 - edit the `/etc/dnsadmin/dnsadmin.conf` and `/etc/dnsadmin/recordtemplates.py`
   files as appropriate for your setup

Then run `dnsadmin --help` for usage instructions.
