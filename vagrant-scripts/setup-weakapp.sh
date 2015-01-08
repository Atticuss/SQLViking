#!/bin/bash

sudo apt-get install git -y
sudo apt-get install unzip -y

mkdir /opt/weakapp
cp -R /vagrant/sinatra-app/* /opt/weakapp

gpg --keyserver hkp://keys.gnupg.net --recv-keys D39DC0E3
\curl -sSL https://get.rvm.io | bash -s stable --ruby
source /home/vagrant/.rvm/scripts/rvm
rvm install 2.0.0
source /usr/local/rvm/scripts/rvm
sudo apt-get install freetds-dev freetds-bin tdsodbc libmysqlclient-dev -y

cd /opt/weakapp
rvm use 2.0.0
bundle install
rake db:create
rake db:migrate
rake db:seed
ruby app.rb


