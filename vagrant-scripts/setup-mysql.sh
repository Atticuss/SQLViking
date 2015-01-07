#!/bin/bash

sudo apt-get install git -y
sudo apt-get install unzip -y

mkdir /opt/sqlviking
cp -R /vagrant/* /opt/sqlviking/

cd /tmp
wget http://www.secdev.org/projects/scapy/files/scapy-2.3.0.zip
unzip scapy-2.3.0.zip
rm -rf scapy-2.3.0.zip
cd scapy-2.*

sudo chown -R vagrant:root /opt/sqlviking/
sudo python setup.py install

cd /opt/sqlviking

