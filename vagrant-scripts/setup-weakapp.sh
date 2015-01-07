#!/bin/bash

sudo apt-get install git -y
sudo apt-get install unzip -y

mkdir /opt/weakapp
cp -R /vagrant/weakapp/* /opt/app

gpg --keyserver hkp://keys.gnupg.net --recv-keys D39DC0E3
\curl -sSL https://get.rvm.io | bash -s stable --ruby
source /home/vagrant/.rvm/scripts/rvm
rvm install 1.9.2

sudo apt-get install freetds-dev freetds-bin tdsodbc libmysqlclient-dev


cd /opt/app
git clone https://github.com/fidalgo/ruby-mssql-example

cd /opt/app/ruby-mssql-example
