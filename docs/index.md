---
organization: Turbot
category: ["software development"]
icon_url: "/images/plugins/turbot/nginx.svg"
brand_color: "#009900"
display_name: "Nginx"
description: "Tailpipe plugin for collecting and querying Nginx access logs."
og_description: "Collect Nginx logs and query them instantly with SQL! Open source CLI. No DB required."
og_image: "/images/plugins/turbot/nginx-social-graphic.png"
---

# Nginx + Tailpipe

[Tailpipe](https://tailpipe.io) is an open-source CLI tool that allows you to collect logs and query them with SQL.

[Nginx](https://nginx.org/) is a popular open-source web server that can also be used as a reverse proxy, load balancer, mail proxy, and HTTP cache.

The [Nginx Plugin for Tailpipe](https://hub.tailpipe.io/plugins/turbot/nginx) allows you to collect and query Nginx access logs using SQL to track activity, monitor trends, detect anomalies, and more!

- Documentation: [Table definitions & examples](https://hub.tailpipe.io/plugins/turbot/nginx/tables)
- Community: [Join #tailpipe on Slack →](https://turbot.com/community/join)
- Get involved: [Issues](https://github.com/turbot/tailpipe-plugin-nginx/issues)

![image](https://raw.githubusercontent.com/turbot/tailpipe-plugin-nginx/main/docs/images/nginx_access_log_terminal.png?type=thumbnail)

## Getting Started

Install Tailpipe from the [downloads](https://tailpipe.io/downloads) page:

```sh
# MacOS
brew install turbot/tap/tailpipe
```

```sh
# Linux or Windows (WSL)
sudo /bin/sh -c "$(curl -fsSL https://tailpipe.io/install/tailpipe.sh)"
```

Install the plugin:

```sh
tailpipe plugin install nginx
```

Configure your table partition and data source:

```sh
vi ~/.tailpipe/config/nginx.tpc
```

```hcl
partition "nginx_access_log" "my_logs" {
  source "file" {
    paths       = ["/var/log/nginx/access/"]
    file_layout = "%{DATA}.log"
  }
}
```

Download, enrich, and save logs from your source ([examples](https://tailpipe.io/docs/reference/cli/collect)):

```sh
tailpipe collect nginx_access_log
```

Enter interactive query mode:

```sh
tailpipe query
```

Run a query:

```sql
select
  remote_addr,
  request_method,
  request_uri,
  status,
  count(*) as request_count
from
  nginx_access_log
group by
  remote_addr,
  request_method,
  request_uri,
  status
order by
  request_count desc;
```

```sh
+---------------+----------------+------------------+--------+---------------+
| remote_addr   | request_method | request_uri      | status | request_count |
+---------------+----------------+------------------+--------+---------------+
| 192.168.1.100 | GET            | /api/users       | 200    | 15243         |
| 10.0.0.50     | POST           | /api/login       | 401    | 8721          |
| 172.16.0.25   | GET            | /static/main.css | 304    | 5432          |
+---------------+----------------+------------------+--------+---------------+
```