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
  #Setup Vulnerable Test App
  config.vm.define :weakapp do |app|

    app.vm.box = "ferventcoder/win2008r2-x64-nocm"
    app.vm.guest = :windows
    
    app.vm.provider "virtualbox" do |v|
      v.gui = true
    end

    app.vm.communicator = "winrm"
    
    app.vm.network "private_network", ip: "192.168.123.123"
    app.vm.network :forwarded_port, guest: 85, host: 85
    app.vm.network :forwarded_port, guest: 3389, host: 1234
    app.vm.network :forwarded_port, guest: 5985, host: 5985, id: "winrm", auto_correct: true
   
    # .NET 4.5
    app.vm.provision :shell, path: "vagrant-scripts/install-dot-net.ps1"  
    app.vm.provision :shell, path: "vagrant-scripts/install-dot-net-45.cmd" 
    
    # Database
    app.vm.provision :shell, path: "vagrant-scripts/install-sql-server.cmd" 
    app.vm.provision :shell, path: "vagrant-scripts/configure-sql-server.ps1"  
    
    #Restore DB
    app.vm.provision :shell, path: "vagrant-scripts/create-database.cmd"
     
    # IIS   
    app.vm.provision :shell, path: "vagrant-scripts/install-iis.cmd"
      
    #Create Website
    app.vm.provision :shell, path: "vagrant-scripts/create-website-folder.ps1"
    app.vm.provision :shell, path: "vagrant-scripts/creating-website-in-iis.cmd"

  end

  config.vm.define :sqlviking do |viking|
    viking.vm.box = "phusion/ubuntu-14.04-amd64"
    viking.vm.guest = :linux

    viking.vm.provider "virtualbox" do |v|
      v.gui = true
    end

    viking.vm.network "private_network", ip: "192.168.123.124"
    viking.vm.provision "shell", path: "vagrant-scripts/setup-sqlviking.sh"

  end
end