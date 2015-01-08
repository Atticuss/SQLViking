#!/bin/bash

sudo apt-get install git -y
sudo apt-get install unzip -y

mkdir /opt/weakapp
cp -R /vagrant/sinatra-app/* /opt/app

gpg --keyserver hkp://keys.gnupg.net --recv-keys D39DC0E3
\curl -sSL https://get.rvm.io | bash -s stable --ruby
source /home/vagrant/.rvm/scripts/rvm
rvm install 2.0.0

sudo apt-get install freetds-dev freetds-bin tdsodbc libmysqlclient-dev

cd /opt/app
bundle install
ruby app.rb


