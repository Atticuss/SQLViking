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
		@users = User.all
	end
end

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
