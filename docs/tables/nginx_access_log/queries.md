# Example Queries for nginx_access_log Table

## Activity Examples

### Daily Request Trends

Count requests per day to identify traffic patterns over time. This query helps visualize usage trends, detect potential traffic anomalies, and understand the overall load on your nginx server across different days.

```sql
select
  strftime(tp_timestamp, '%Y-%m-%d') as request_date,
  count(*) as request_count
from
  nginx_access_log
group by
  request_date
order by
  request_date asc;
```

### Top 10 Clients by Request Count

List the top 10 client IP addresses making requests. This query helps identify the most active clients, potentially revealing heavy users, bot traffic, or unusual access patterns that might require further investigation.

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

### HTTP Status Code Distribution

Analyze the distribution of HTTP status codes. This query helps understand the overall health of your websites and server, identifying success rates, client errors, and server errors.

```sql
select
  status,
  count(*) as count,
  round(count(*) * 100.0 / sum(count(*)) over (), 2) as percentage
from
  nginx_access_log
group by
  status
order by
  count desc;
```

## Traffic Analysis

### Top HTTP Methods

Analyze the distribution of HTTP methods in your requests.

```sql
select
  request_method,
  count(*) as request_count,
  round(count(*) * 100.0 / sum(count(*)) over (), 2) as percentage
from
  nginx_access_log
group by
  request_method
order by
  request_count desc;
```

### Busiest Days

Identify the hours with the most traffic.

```sql
select
  date_trunc('day', tp_timestamp) as day,
  count(*) as request_count,
  sum(body_bytes_sent) as total_bytes_sent
from
  nginx_access_log
group by
  day
order by
  request_count desc;
```

### Busiest Hours

Identify the hours with the most traffic.

```sql
select
  date_trunc('hour', tp_timestamp) as hour,
  count(*) as request_count,
  sum(body_bytes_sent) as total_bytes_sent
from
  nginx_access_log
group by
  hour
order by
  request_count desc;
```

### Most Requested URLs

Find the most frequently accessed URLs.

```sql
select
  request_uri,
  count(*) as hits,
  avg(body_bytes_sent) as avg_bytes_sent
from
  nginx_access_log
group by
  request_uri
order by
  hits desc
limit 20;
```

## Error Analysis

### Error Distribution by Status Code

Break down of different types of errors.

```sql
select
  status,
  count(*) as error_count
from
  nginx_access_log
where
  status >= 400
group by
  status
order by
  error_count desc;
```

### Client Errors vs Server Errors

Compare the number of client (4xx) vs server (5xx) errors over time.

```sql
select
  date_trunc('hour', tp_timestamp) as hour,
  count(*) filter (where status >= 400 and status < 500) as client_errors,
  count(*) filter (where status >= 500) as server_errors
from
  nginx_access_log
where
  status >= 400
group by
  hour
order by
  hour desc;
```

## Performance Monitoring

### Large Response Analysis

Find requests returning large amounts of data.

```sql
select
  tp_timestamp,
  remote_addr,
  request_method,
  request_uri,
  body_bytes_sent
from
  nginx_access_log
where
  body_bytes_sent > 1000000  -- More than 1MB
order by
  body_bytes_sent desc
limit 20;
```

## User Agent Analysis

### Browser Distribution

Analyze which browsers are accessing your site.

```sql
select
  case
    when http_user_agent like '%Chrome%' then 'Chrome'
    when http_user_agent like '%Firefox%' then 'Firefox'
    when http_user_agent like '%Safari%' then 'Safari'
    when http_user_agent like '%MSIE%' or http_user_agent like '%Trident%' then 'Internet Explorer'
    when http_user_agent like '%Edge%' then 'Edge'
    when http_user_agent like '%bot%' or http_user_agent like '%Bot%' or http_user_agent like '%spider%' then 'Bot'
    else 'Other'
  end as browser,
  count(*) as request_count
from
  nginx_access_log
group by
  browser
order by
  request_count desc;
```

### Bot Traffic Analysis

Identify and analyze bot traffic.

```sql
select
  http_user_agent,
  count(*) as request_count,
  sum(body_bytes_sent) as total_bytes_sent
from
  nginx_access_log
where
  regexp_matches(http_user_agent, '(?i)(bot|crawler|spider)')
group by
  http_user_agent
order by
  request_count desc
limit 20;
```

## Security Analysis

### Potential Security Threats

Identify potentially malicious requests.

```sql
select
  tp_timestamp,
  remote_addr,
  request_method,
  request_uri,
  status,
  http_user_agent
from
  nginx_access_log
where
  regexp_matches(request_uri, '(?i)(wp-admin|/admin|\.sql|\.git)')
  or request_uri like '%/../%'
  or request_uri like '%<script>%'
  or request_uri like '%union select%'
order by
  tp_timestamp desc
limit 100;
```

### Rate Limiting Analysis

Find potential DDoS attempts or aggressive crawlers.

```sql
select
  remote_addr,
  count(*) as request_count,
  count(distinct request_uri) as unique_urls,
  min(tp_timestamp) as first_request,
  max(tp_timestamp) as last_request
from
  nginx_access_log
where
  date_diff('minute', tp_timestamp, cast(current_timestamp as timestamp)) <= 60
group by
  remote_addr
having
  count(*) > 1000  -- Adjust threshold as needed
order by
  request_count desc;
```

## Upstream Analysis

### Upstream Response Times

Analyze upstream server response times.

```sql
select
  upstream_addr,
  count(*) as request_count,
  avg(upstream_response_time) as avg_response_time,
  max(upstream_response_time) as max_response_time,
  percentile_cont(0.95) within group (order by upstream_response_time) as p95_response_time
from
  nginx_access_log
where
  upstream_addr is not null
group by
  upstream_addr
order by
  avg_response_time desc
limit 20;
```

### SSL Protocol Usage

Analyze SSL/TLS protocol distribution.

```sql
select
  ssl_protocol,
  ssl_cipher,
  count(*) as connection_count,
  round(count(*) * 100.0 / sum(count(*)) over (), 2) as percentage
from
  nginx_access_log
where
  ssl_protocol is not null
group by
  ssl_protocol,
  ssl_cipher
order by
  connection_count desc;
```

## Detection Examples

### SSL Cipher Vulnerabilities

Detect usage of deprecated or insecure SSL ciphers. This query helps identify potential security risks by highlighting the use of outdated or vulnerable SSL protocols and ciphers.

```sql
select
  ssl_cipher,
  ssl_protocol,
  count(*) as request_count
from
  nginx_access_log
where
  ssl_protocol in ('TLSv1.1', 'TLSv1', 'SSLv3', 'SSLv2') -- Insecure protocols
group by
  ssl_cipher,
  ssl_protocol
order by
  request_count desc;
```

### Suspicious HTTP Methods

Detect potentially dangerous HTTP methods that could indicate attempted exploits or misconfigured clients.

```sql
select
  request_method,
  request_uri,
  remote_addr,
  status,
  count(*) as request_count
from
  nginx_access_log
where
  request_method not in ('GET', 'POST', 'HEAD', 'OPTIONS')
group by
  request_method,
  request_uri,
  remote_addr,
  status
order by
  request_count desc;
```

### Failed Authentication Attempts

Identify potential brute force attacks by detecting multiple failed authentication attempts (401 status codes).

```sql
select
  remote_addr,
  count(*) as failed_attempts,
  min(tp_timestamp) as first_attempt,
  max(tp_timestamp) as last_attempt,
  array_agg(distinct request_uri) as attempted_urls
from
  nginx_access_log
where
  status = 401
group by
  remote_addr
having
  count(*) > 10
order by
  failed_attempts desc;
```

### Abnormal Response Sizes

Detect unusually large or small responses that might indicate data exfiltration or failed attacks.

```sql
select
  request_uri,
  remote_addr,
  body_bytes_sent,
  status,
  tp_timestamp
from
  nginx_access_log
where
  (body_bytes_sent > 10000000) -- Extremely large responses (>10MB)
  or (status = 200 and body_bytes_sent < 100) -- Suspiciously small successful responses
order by
  body_bytes_sent desc;
```

### Suspicious User Agents

Identify requests with potentially malicious or suspicious user agents.

```sql
select
  http_user_agent,
  count(*) as request_count,
  array_agg(distinct remote_addr) as source_ips,
  array_agg(distinct request_uri) as requested_urls
from
  nginx_access_log
where
  http_user_agent like '%curl%'
  or http_user_agent like '%wget%'
  or http_user_agent like '%python%'
  or http_user_agent like '%sqlmap%'
  or http_user_agent like '%nikto%'
  or http_user_agent = '-'
  or http_user_agent is null
group by
  http_user_agent
order by
  request_count desc;
```

### Error Spikes

Detect sudden spikes in error rates that might indicate attacks or system issues.

```sql
select
  date_trunc('minute', tp_timestamp) as minute,
  count(*) as total_requests,
  count(*) filter (where status >= 400) as error_count,
  round(count(*) filter (where status >= 400) * 100.0 / count(*), 2) as error_rate
from
  nginx_access_log
group by
  minute
having
  count(*) > 100 -- Minimum request threshold
  and (count(*) filter (where status >= 400) * 100.0 / count(*)) > 20 -- Error rate > 20%
order by
  minute desc;
```

### Directory Traversal Attempts

Identify potential directory traversal attacks.

```sql
select
  remote_addr,
  request_uri,
  status,
  tp_timestamp,
  http_user_agent
from
  nginx_access_log
where
  request_uri like '%../%'
  or request_uri like '%/../%'
  or request_uri like '%/./%'
  or request_uri like '%/...%'
  or request_uri like '%\\..\\%'
order by
  tp_timestamp desc;
```

### SQL Injection Attempts

Detect potential SQL injection attempts in request URIs.

```sql
select
  remote_addr,
  request_uri,
  status,
  tp_timestamp,
  http_user_agent
from
  nginx_access_log
where
  request_uri like '%SELECT%'
  or request_uri like '%UNION%'
  or request_uri like '%INSERT%'
  or request_uri like '%UPDATE%'
  or request_uri like '%DELETE%'
  or request_uri like '%DROP%'
  or request_uri like '%1=1%'
  or request_uri like '%'='%'
order by
  tp_timestamp desc;
```

### Geographic Anomalies

If you have IP geolocation data, detect requests from unusual locations or known problematic regions.

```sql
select
  remote_addr,
  count(*) as request_count,
  array_agg(distinct request_uri) as accessed_urls,
  min(tp_timestamp) as first_seen,
  max(tp_timestamp) as last_seen
from
  nginx_access_log
where
  -- Replace with actual IP ranges or geolocation logic
  remote_addr like '192.%'
  or remote_addr like '10.%'
  or remote_addr like '172.16.%'
group by
  remote_addr
order by
  request_count desc;
```