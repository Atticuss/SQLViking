class UserMimic
	include Sidekiq::Worker

	def perform(name, count)
		User.all
	end
end