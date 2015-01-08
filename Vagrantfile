# -*- mode: ruby -*-
# vi: set ft=ruby :

# Vagrantfile API/syntax version. Don't touch unless you know what you're doing!
VAGRANTFILE_API_VERSION = "2"

ENV['VAGRANT_DEFAULT_PROVIDER'] = 'virtualbox'

if ! File.exists?('./NDP451-KB2858728-x86-x64-AllOS-ENU.exe')
  puts '.Net 4.5 installer could not be found!'
  puts "Please run:\n  wget http://download.microsoft.com/download/1/6/7/167F0D79-9317-48AE-AEDB-17120579F8E2/NDP451-KB2858728-x86-x64-AllOS-ENU.exe"
  exit 1
end

if ! File.exists?('./SQLEXPRWT_x64_ENU.exe')
  puts 'SQL Server installer could not be found!'
  puts "Please run:\n  wget http://download.microsoft.com/download/0/4/B/04BE03CD-EAF3-4797-9D8D-2E08E316C998/SQLEXPRWT_x64_ENU.exe"
  exit 1
end

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|

##########Setup Vulnerable Test App ###########

  config.vm.define :weakapp do |app|
    app.vm.box = "phusion/ubuntu-14.04-amd64"

    app.vm.provider "virtualbox" do |v|
        v.gui = true
    end

    app.vm.network "private_network", ip: "192.168.123.10"
    app.vm.network :forwarded_port, guest:4567, host:4567
    app.vm.provision "shell", path: "vagrant-scripts/setup-weakapp.sh"
  end

########## Setup MSSQL Server ###########

  config.vm.define :mssql do |sql|
    sql.vm.box = "ferventcoder/win2008r2-x64-nocm"
    sql.vm.guest = :windows
    sql.vm.provider "virtualbox" do |v|
      v.gui = true
    end

    sql.vm.communicator = "winrm"
    sql.vm.network "private_network", ip: "192.168.50.4"
    sql.vm.network "forwarded_port", guest: 3389, host: 3389
    sql.vm.network "forwarded_port", guest: 1433, host: 1433

    sql.vm.provision :shell, path: "vagrant-scripts/install-dot-net.ps1"
    sql.vm.provision :shell, path: "vagrant-scripts/install-sql-server.cmd"
    sql.vm.provision :shell, path: "vagrant-scripts/configure-sql-port.ps1"
    sql.vm.provision :shell, path: "vagrant-scripts/enable-rdp.ps1"

  end

########## Setup MySQL ###############
  config.vm.define :mysql do |mysql|
      mysql.vm.box = "phusion/ubuntu-14.04-amd64"

      mysql.vm.provider "virtualbox" do |v|
        v.gui = true
      end

      mysql.vm.network "private_network", ip: "192.168.123.13"
      mysql.vm.network :forwarded_port, guest: 3306, host: 3306
      mysql.vm.provision "shell", path: "vagrant-scripts/setup-mysql.sh"
      #NEED TO CHANGE BIND ADDRESS >.<

  end

########## Setup SQLViking ###########

  config.vm.define :sqlviking do |viking|
    viking.vm.box = "phusion/ubuntu-14.04-amd64"

    viking.vm.provider "virtualbox" do |v|
      v.gui = true
    end

    viking.vm.network "private_network", ip: "192.168.123.12"
    viking.vm.provision "shell", path: "vagrant-scripts/setup-sqlviking.sh"

  end
end