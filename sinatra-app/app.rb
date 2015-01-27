require 'sidekiq'
require 'sinatra'
require 'sinatra/base'
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

class UserMimic
	include Sidekiq::Worker
	def perform()
		puts User.all
		sleep(5.seconds)
		puts Comment.all
		sleep(5.seconds)
		puts Account.all
		sleep(5.seconds)
		User.find(1)
		sleep(5.seconds)
		user = User.find_by(name: "Ken")
		puts user
		puts Comment.first
		sleep(5.seconds)
		puts Account.first
		sleep(5.seconds)
		Comment.create(name: "Go Team", message: "Win Win")
	end
end
# Sidekiq to Mimic Users #

class WeakApp < Sinatra::Base
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
		UserMimic.perform_async()
		erb :index
	end
end
