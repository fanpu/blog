---
layout: page
title: Dev Cheat Sheets
permalink: /cheat_sheets/
nav: sidebar-sample
---
Even the best of us sometimes forget common administrative commands on the
terminal when we
haven't used them in a while. I record down those that I find useful here for
my own reference. You may find some of these helpful as well.

<h2>{{ site.data.navigation.docs_cheatsheet_title }}</h2>
<ul>
   {% for item in site.data.navigation.docs %}
      <li><a href="{{ item.url | relative_url }}">{{ item.title }}</a></li>
   {% endfor %}
</ul>

### Linux
#### > General
- Re-index `locate` database
```
updatedb
```

#### > Arch Linux
- Installation without prompts (usually for AUR)
```
pacman -S --noconfirm <package>
```
- Manage `.pacnew` and `.pacsave` files
```
pacdiffviewer
```
#### > Curl
- `curl` an application with JSON payload
```shell
curl -H "Content-Type: application/json" -d '{"text": "Hello world"}' http://localhost:3000/api
```

### Postgres
#### > Connecting

- To connect to a Postgres server locally:
```
psql -U <username>
```

- To connect to a Postgres server on a remote machine:
```
psql -h <hostname> -U <username> -d <database>
```

#### > Commands
- `\c <database>`: Connect to a database
- `\d <table>`: Show table definition
- `\l`: List databases
- `\dn`: List schemas
- `\q`: Quit

#### > Administration
- `\du`: List users
- `create role <user>`: Create role with existing username

### Docker
#### > Docker
- Build a Docker image
```
docker build -t <image_name>
```
- List Docker images
```
docker images
```
- Pull a Docker image
```
docker pull <image_name>
```
- Run a Docker container in the background, with port mapping and name provided. Tag name is defaulted to `latest` if unspecified.
```
docker run -d -p <container_port>:<host_port> --name <name> <image_name>:<tag_name>
```
- Run a Docker container interactively, `bash` in this example
```
docker run -it <name> bash
```
- List containers. The `-a` flag shows all containers.
```
docker ps -a
```
- Stop a container
```
docker stop <name>
```
- Remove a container
```
docker rm <name>
```
- Remove an image
```
docker rmi <image_name>:<tag_name>
```
- To run a Docker container inside a Docker container, pass in the Docker
  socket as a volume
```
docker run -v /var/run/docker.sock:/var/run/docker.sock
```


#### > Docker Compose
- Bring up containers in detached mode:
```
docker-compose up -d
```
- Bring down containers
```
docker-compose down
```

### Vagrant
- Create a Vagrant configuration file for Ubuntu 14.04 (Trusty Tahr) 64-bit virtual machine image
```shell
vagrant init ubuntu/trusty64
```
- Start VM based on Vagrantfile
```
vagrant up
```
- SSH into VM
```shell
vagrant ssh
```
- SSH into named VM
```shell
vagrant ssh <vm_name>
```
- Get port forwarding information of a machine
```
vagrant port <vm_name>
```
- Type `exit` to quit the SSH session
- To output SSH connection details
```shell
vagrant ssh-config
```
- SSH from command line using information above
```
ssh vagrant@127.0.0.1 -p 2222 -i /path/to/private/key
```
- Get status of machines
```
vagrant status
```
- Destroy VM
```
vagrant destroy <vm_name>
```
- Sample Vagrantfile

```
# -*- mode: ruby -*-
# # vi: set ft=ruby :

Vagrant.configure("2") do |config|

  config.vm.define "web" do |web|
    web.vm.box = "bento/ubuntu-14.04"
    web.vm.network "forwarded_port", guest: 80, host: 8080
    web.vm.synced_folder "./html", "/var/www/html/class"
    web.vm.provision :shell, path: "bootstrap.sh"
  end

  config.vm.define "db" do |db|
    db.vm.box = "bento/ubuntu-12.04"
    db.vm.network "forwarded_port", guest: 3306, host: 3306
    db.vm.hostname = "dbserver"
    db.vm.provision :shell, path: "db-bootstrap.sh"
  end

end
```


### Jekyll
- Serve a Jekyll project locally:
```
bundle exec jekyll serve
```
- Build for production
```
JEKYLL_ENV=production bundle exec jekyll build
```

### Chef
- Generate new cookbook
```
chef generate cookbook <name>
```
- Execute cookbook with config file and JSON data
```
chef-solo -c <config_file> -j <json_file>
```
- Converge based on cookbook
```
kitchen converge
```
- Get instances convergence status
```
kitchen list
```
- Remove instances
```
kitchen destroy
```

### NPM
- Install a package globally
```
npm install -g <package_name>
```

### dpkg
- Build package
```
dpkg-deb --build myapp_1.0
```
- Get information about package
```
dpkg-deb -I myapp_1.0.deb
```
- Get contents of package
```
dpkg-deb -c myapp_1.0.deb
```
- Install package
```
dpkg-deb -i myapp_1.0.deb
```

### apt
- List installed packages
```
apt list --installed
```
- Get information about package
```
apt show <package_name>
```

### Gem
- Install package without ri and rdoc
```
gem install --no-ri --no-rdoc <name>
```

### AWS
- Configure AWS credentials
```
aws configure
```
- Get information about EC2 instances in `us-east-1` region
```
aws ec2 describe-instances --region us-east-1
```
- Run an EC2 instance with specified AMI
```
aws ec2 run-instances --image-id <ami_id> --instance-type t2.micro --region
us-east-1
```
- Validate CloudFormation template
```
aws --region us-east-1 cloudformation validate-template --template-body
file://./ec2.yml
```
- Create CloudFormation stack
```
aws --region us-east-1 cloudformation create-stack --stack-name <name>
--parameters file://./ec2-parameters.json --template-body file://./ec2.yml
```
