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
### Jekyll
- Serve a Jekyll project locally:
```
bundle exec jekyll serve
```
- Build for production
```
JEKYLL_ENV=production bundle exec jekyll build
```