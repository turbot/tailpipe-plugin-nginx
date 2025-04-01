---
title: "Tailpipe Table: nginx_access_log - Query Nginx Access Logs"
description: "Nginx access logs capture detailed information about requests processed by the Nginx web server. This table provides a structured representation of the log data, including request details, client information, response codes, and processing times."
---

# Table: nginx_access_log - Query Nginx Access Logs

The `nginx_access_log` table allows you to query Nginx web server access logs. This table provides detailed information about HTTP requests processed by your Nginx servers, including client details, request information, response codes, and timing data.

By default, this table uses the Nginx "combined" log format:

```
$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
```

If your logs use a different format, you can specify a custom format as shown in the example configurations below.

## Configure

Create a [partition](https://tailpipe.io/docs/manage/partition) for `nginx_access_log`:

```sh
vi ~/.tailpipe/config/nginx.tpc
```

```hcl
partition "nginx_access_log" "my_nginx_logs" {
  source "file" {
    paths       = ["/var/log/nginx/access"]
    file_layout = `%{DATA}.log`
  }
}
```

## Collect

[Collect](https://tailpipe.io/docs/manage/collection) logs for all `nginx_access_log` partitions:

```sh
tailpipe collect nginx_access_log
```

Or for a single partition:

```sh
tailpipe collect nginx_access_log.my_nginx_logs
```

## Query

**[Explore example queries for this table →](https://hub.tailpipe.io/plugins/turbot/nginx/queries/nginx_access_log)**

### Failed Requests

Find failed HTTP requests (with status codes 400 and above) to troubleshoot server issues.

```sql
select
  tp_timestamp,
  remote_addr,
  status,
  request_method,
  request_uri,
  server_protocol,
  body_bytes_sent
from
  nginx_access_log
where
  status >= 400
order by
  tp_timestamp desc;
```

### Large Response Analysis

Find requests returning large amounts of data.

```sql
select
  tp_timestamp,
  remote_addr,
  request_method,
  request_uri,
  body_bytes_sent,
  http_referer,
  http_user_agent
from
  nginx_access_log
where
  body_bytes_sent > 1000000  -- More than 1MB
order by
  body_bytes_sent desc;
```

### Top 10 High Traffic Sources

Identify the IP addresses generating the most traffic.

```sql
select
  remote_addr,
  count(*) as request_count,
  count(distinct request_uri) as unique_urls,
  sum(body_bytes_sent) as total_bytes_sent
from
  nginx_access_log
group by
  remote_addr
order by
  request_count desc
limit 10;
```

## Example Configurations

### Basic configuration

Collect standard Nginx access logs from the default location.

```hcl
partition "nginx_access_log" "my_nginx_logs" {
  source "file" {
    paths       = ["/var/log/nginx/access"]
    file_layout = `%{DATA}.log`
  }
}
```

### Collect logs with custom field selection

Define a minimal format that only includes specific fields you need. See the [Nginx log format documentation](http://nginx.org/en/docs/http/ngx_http_log_module.html#log_format) for a complete list of available fields.

```hcl
format "nginx_access_log" "minimal" {
  layout = `$time_local $request_uri $status $body_bytes_sent $remote_addr`
}

partition "nginx_access_log" "minimal_logs" {
  source "file" {
    format      = format.nginx_access_log.minimal
    paths       = ["/var/log/nginx/minimal"]
    file_layout = `%{DATA}.log`
  }
}
```

### Filter logs by HTTP error status codes

Use the filter argument to collect only requests with HTTP error status codes (4xx and 5xx).

```hcl
partition "nginx_access_log" "http_errors" {
  filter = "status >= 400"
  
  source "file" {
    paths       = ["/var/log/nginx/access"]
    file_layout = `%{DATA}.log`
  }
}
```

### Collect logs from multiple server directories

Collect logs from multiple directories or servers.

```hcl
partition "nginx_access_log" "multi_server_logs" {
  source "file" {
    paths = [
      "/var/log/nginx/server1/access",
      "/var/log/nginx/server2/access",
      "/var/log/nginx/server3/access"
    ]
    file_layout = `%{DATA}.log`
  }
}
```

### Collect logs from gzip archives

If your log files are compressed, you can still collect from them.

```hcl
partition "nginx_access_log" "compressed_logs" {
  source "file" {
    paths       = ["/var/log/nginx/archive"]
    file_layout = `%{DATA}.log.gz`
  }
}
```

### Collect logs from ZIP archives

For logs archived in ZIP format, you can collect them directly.

```hcl
partition "nginx_access_log" "zip_logs" {
  source "file" {
    paths       = ["/var/log/nginx/archive"]
    file_layout = `%{DATA}.log.zip`
  }
}
```

### Collect logs from S3 bucket

For logs archived in S3, commonly used for long-term storage and centralized logging.

```hcl
connection "aws" "logging" {
  profile = "logging-account"
}

partition "nginx_access_log" "s3_logs" {
  source "aws_s3_bucket" {
    connection  = connection.aws.logging
    bucket      = "nginx-access-logs"
    prefix      = "logs/"
    file_layout = `%{YEAR:year}/%{MONTHNUM:month}/%{MONTHDAY:day}/access.log.gz`
  }
}
```

