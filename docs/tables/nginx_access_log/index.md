---
title: "Tailpipe Table: nginx_access_log - Query Nginx Access Logs"
description: "Nginx access logs capture detailed information about requests processed by the Nginx web server. This table provides a structured representation of the log data, including request details, client information, response codes, and processing times."
---

# Table: nginx_access_log - Query Nginx Access Logs

The `nginx_access_log` table allows you to query Nginx web server access logs. This table provides detailed information about HTTP requests processed by your Nginx servers, including client details, request information, response codes, and timing data.

## Configure

Create a [partition](https://tailpipe.io/docs/manage/partition) for `nginx_access_log`:

```sh
vi ~/.tailpipe/config/nginx.tpc
```

```hcl
partition "nginx_access_log" "my_nginx_logs" {
  source "file" {
    paths       = ["/var/log/nginx/access"]
    file_layout = "%{DATA}.log"
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
  tp_timestamp desc
limit 10;
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
  body_bytes_sent desc
limit 10;
```

### High Traffic Sources

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

