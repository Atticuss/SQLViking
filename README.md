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
vagrant up sqlviking mysql weakapp
```

Once these three VMs are running, the weak application should be available for submitting requests. Check this in your browser by navigating to `localhost:4567`.

(open a new terminal window)
```bash
vagrant ssh sqlviking
```

Inside of the sqlviking VM
```bash
vagrant@ubuntu-14:/opt/sqlviking$      cd /opt/sqlviking
vagrant@ubuntu-14:/opt/sqlviking$      sudo python sqlviking.py
```

##Common Issues
###SQLViking isn't picking anything up :(
Make sure you ran sqlviking with `sudo` or it won't work properly because scapy doesn't have the appropriate access to the network interface