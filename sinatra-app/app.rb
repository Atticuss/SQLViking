require 'sidekiq'
require 'sinatra'
require "sinatra/activerecord"

# Server/DB setup #
set :database_file, "./database_mysql.yml"
set :bind, '0.0.0.0'
set :daemon, true

# Active Record Initialization #

class Comment < ActiveRecord::Base
end

class User < ActiveRecord::Base
end

class Account < ActiveRecord::Base
end

# Sidekiq to Mimic Users #

class UserMimic
	include Sidekiq::Worker

	def perform(name, count)
		User.all
		sleep(5.seconds)
		Comment.all
		sleep(5.seconds)
		Account.all
		sleep(5.seconds)
		User.find(1)
		sleep(5.seconds)
		User.find_by(name: "Ken")
		Comment.first
		sleep(5.seconds)
		Account.first
		sleep(5.seconds)
	end
end

# Routing #
get '/' do
  @comments = Comment.all
  erb :index
end

post '/' do
  Comment.create!(
    name:    params[:name],
    message: params[:message]
  )
  redirect '/'
end

# App with User mimic function running #

get '/usermimic' do
	@comments = Comment.all
	UserMimic.perform_async('name', 3)
	erb :index
end
