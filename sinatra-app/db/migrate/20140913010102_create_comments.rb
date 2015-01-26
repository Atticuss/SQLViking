class CreateComments < ActiveRecord::Migration
  def change
    create_table :comments do |t|
      t.string :name
      t.text   :message
    end

    create_table :users do |t|
  		t.string :name
  		t.string :email
  		t.string :gender
  		t.string :password
  		t.string :password_confirmation
  	end

  	 create_table :accounts do |t|
  		t.string :name
  		t.decimal :balance
  		t.string :status
  		t.text :notes
  	end
  end
end
