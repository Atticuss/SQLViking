require 'sidekiq'
require 'sinatra'
require "sinatra/activerecord"

class UserMimic
	include Sidekiq::Worker

	def perform(name, count)
		@users = User.all
	end
end

set :database_file, "./database_mysql.yml"
set :bind, '0.0.0.0'
set :daemon, true

class Comment < ActiveRecord::Base
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

get '/usermimic' do
	@comments = Comment.all
	UserMimic.perform_async('name', 3)
	erb :index
end
