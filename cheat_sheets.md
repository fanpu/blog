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
- Create a Vagrant configuration file for Ubuntu 14.04 (Trusty Tahr) 64-bit virtual machine image, and boot it
```shell
vagrant init ubuntu/trusty64
vagrant up
```

- SSH into virtual machine
```shell
vagrant ssh
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
- Execute chef cookbook with config file and JSON data
```
chef-solo -c <CONFIG_FILE> -j <JSON_FILE>
```
