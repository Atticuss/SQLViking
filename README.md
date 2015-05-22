SQLViking
=========

```sudo python sqlviking.py -c <sqlviking.conf> ```

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
#####NOTE: We're having some trouble getting the background process to function properly on the web app, so if you run it in the order above the weakapp will run last. The server will be running correctly upon deployment:

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
###Is it working yet?
Actually, yes!
###SQLViking isn't picking anything up :(
Make sure you ran sqlviking with `sudo` or it won't work properly because scapy doesn't have the appropriate access to the network interface. Virtual interfaces run by virtualbox also don't seem to play nice with any kind of pcap tools including wireshark. Trying setting up a test box with VMWare instead.
###I can't inject in the vagrant environment
We know. Scapy (the library we use for picking/putting packets on the wire) doesn't play nice with virtual interfaces. Working to resolve now.
