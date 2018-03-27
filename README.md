Catalog App
===========
___

This is an app that dispalys a catalog of items. A logged in user can  
add, edit or delete an item.  
This app project is part of the requirements for a nanodegree credential  
from [udcity](www.udacity.com)

Software Requirements 
---------------------  
The following softwares are required in order to run this app
* [virtualbox](https://www.virtualbox.org)
* [vagrant virtual machine](http://vagrantup.com)
* udacity's fullstack nanodegree virtual machine available on [github](http://github.com/udacity/fullstack-nanodegree-vm)

How to Run the project
----------------------
* Install the virtualbox and vagrant software on your machine  
* Navigate to the vagrant directory you downloaded from udacity's github repo  
* Run the command _vagrant up_ (this may take a while if you're running it for the first time)  
* Run _vagrant ssh_ to connect to the virtual machine from your local machine  
* Navigate to the vagrant directory with _cd /vagrant_  
* Navigate to the directory where you placed the downloaded project from github  
* Run _python database\_setup.py_ to setup the database  
* Run _python items.py_ to load the project with some few items  
* Run _python catalog\_project.py_ start the server  
* visit **localhost:8000** on your browser to start interacting with the app 


