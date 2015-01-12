SQLViking
=========

Tool is broken up into two pieces:
  1. Scout: passively reads and logs SQL queries and their responses on the wire
  2. Pillage: leverages TCP injection to execute arbitrary queries and parse responses without needing credentials


TDS (tabular data stream) parsing functionality forked from pytds: https://github.com/denisenkom/pytds

MySQL parsing functionality forked from PyMySQL: https://github.com/PyMySQL

Currently only functional on Linux due to some hackery using sigs to make raw_input() non-blocking

Requires: scapy, Python 2.7.x

##Deploying the DEMO MySQL Environment
(assumes vagrant is installed on your machine)
```bash
vagrant box add phusion/ubuntu-14.04-amd64
cd $SQLVIKING_HOME
vagrant up mysql weakapp
```
(open a new terminal window)
```bash
vagrant up sqlviking
```

Once these three VMs are running, the weak application should be available for submitting requests. Check this in your browser by navigating to `localhost:4567`.

Once you've verified the weak application is running, start up SQLViking
```bash
vagrant ssh sqlviking
```

Inside of the sqlviking VM
```bash
vagrant@ubuntu-14:/opt/sqlviking$      cd /opt/sqlviking
vagrant@ubuntu-14:/opt/sqlviking$      python sqlviking.py
```


