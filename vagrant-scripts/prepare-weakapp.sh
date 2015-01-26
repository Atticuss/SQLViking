#!/bin/bash

sudo apt-get install git -y
sudo apt-get install unzip -y

gpg --keyserver hkp://keys.gnupg.net --recv-keys D39DC0E3
\curl -sSL https://get.rvm.io | bash -s stable --ruby=2.0.0
source /home/vagrant/.rvm/scripts/rvm
source /usr/local/rvm/scripts/rvm

#Grab Dependencies
sudo apt-get install freetds-dev freetds-bin tdsodbc libmysqlclient-dev redis-server -y