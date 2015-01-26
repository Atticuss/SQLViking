#!/bin/bash

mkdir /opt/weakapp
cp -R /vagrant/sinatra-app/* /opt/weakapp

#Start Redis Server
redis-server &

cd /opt/weakapp
rvm use 2.0.0
bundle install
bundle exec sidekiq -r ./app.rb &
rake db:create
rake db:migrate
rake db:seed
rackup -D -p 4567