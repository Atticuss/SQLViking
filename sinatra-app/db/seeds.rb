user_list = [
	["Ken","ken@ken.com","male","P@44word","P@44word"],
	["Bob","bob@bob.com","male","P@44word123","P@44word123"],
	["Jonn","jonn@aero.net","male","Flapper","Flapper"],
	["Amy","amy@amy.net","female","amyrulez","amyrulez"],
	["Josh","josh@google.com","male","maria","maria"],
	["Pat","pat@b2lef.com","male","apples","apples"],
	["Penny","penny@penny.net","female","nowords","nowords"],
	["Art","art@monk.com","male","redskins","redskins"]
]

account_list = [
	["Primary",103021,"Good","In Good standing"],
	["Checking",22349,"Good","Getting there"],
	["Credit",-3041,"Negative","Need to pay this off"],
	["Savings",100,"Neutral","Running Low"]
]

comment_list = [
	["Go Team","Doing very well guys"]
]

user_list.each do |name, email, gender, password, password_confirmation|
	User.create( name: name, email: email, gender: gender, password: password, password_confirmation: password_confirmation)
end

account_list.each do |name, balance, status, notes|
	Account.create(name: name, balance: balance, status: status, notes: notes )
end

comment_list.each do |name, message|
	Comment.create(name: name, message: message)
end