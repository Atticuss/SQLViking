#!/bin/bash
sudo apt-get update
sudo apt-get upgrade -y

mkdir /opt/sqlviking
cp -R ~/vagrant/ /opt/sqlviking/