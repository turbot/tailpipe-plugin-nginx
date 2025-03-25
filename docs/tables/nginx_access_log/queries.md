# Example Queries for nginx_access_log Table

## Activity Examples

### Daily Request Trends

Count requests per day to identify traffic patterns over time. This query provides a comprehensive view of daily request volume, helping you understand usage patterns, peak periods, and potential seasonal variations in web traffic. The results can be used for capacity planning, identifying anomalies, and tracking the impact of site changes or marketing campaigns.

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

### Top 10 IP Addresses by Total Bytes Sent

List the top 10 IP addresses by total bytes sent. This query helps identify the most bandwidth-intensive clients, revealing potential bandwidth abuse, heavy users that might need rate limiting, or unusual access patterns that could indicate automated traffic. Understanding traffic distribution across clients is crucial for optimizing content delivery and resource allocation.

```sql
select
  remote_addr,
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

Analyze the distribution of HTTP status codes across your web traffic. This query provides essential insights into server health and client behavior by breaking down success rates, client errors, and server errors. Understanding this distribution helps identify potential issues, monitor service quality, and track the impact of server configuration changes.

```sql
select
  status,
  count(*) as count,
  round(count(*) * 100.0 / sum(count(*)) over (), 3) as percentage
from
  nginx_access_log
group by
  status
order by
  count desc;
```

## Traffic Analysis

### Top HTTP Methods

Analyze the distribution of HTTP methods in your requests. This query reveals how clients interact with your server, helping identify unusual method usage patterns, potential security concerns, and API utilization trends. Understanding method distribution is crucial for security monitoring and ensuring proper server configuration.

```sql
select
  request_method,
  count(*) as request_count,
  round(count(*) * 100.0 / sum(count(*)) over (), 3) as percentage
from
  nginx_access_log
group by
  request_method
order by
  request_count desc;
```

### Busiest Days

Identify the days with the highest request volume. This analysis helps optimize resource allocation, plan maintenance windows, and understand traffic patterns across different time periods. The data can be used to correlate traffic spikes with events or promotions and guide infrastructure scaling decisions.

```sql
select
  strftime(tp_timestamp, '%Y-%m-%d') as day,
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

Track hourly traffic patterns to identify peak usage periods. This information is invaluable for scheduling maintenance, optimizing resource allocation, and ensuring adequate capacity during high-traffic periods. Understanding hourly patterns helps in making informed decisions about infrastructure scaling and content delivery optimization.

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

Analyze the most frequently accessed URLs on your nginx server. This query reveals popular content and high-demand resources, helping optimize caching strategies and content distribution. Understanding URL access patterns is essential for improving user experience and server performance.

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

Analyze the distribution of HTTP error responses across your web traffic. This query helps identify specific types of errors affecting your service, their frequency, and potential patterns that might indicate configuration issues or missing resources. Understanding error distribution is crucial for maintaining service quality and user experience.

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

## Performance Monitoring

### Large Response Analysis

Identify requests generating substantial data transfer volumes. This query helps detect abnormally large responses that might impact server performance or indicate potential data exfiltration attempts. Understanding large response patterns is crucial for optimizing bandwidth usage, content delivery, and maintaining efficient server operation.

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

Analyze the distribution of client browsers accessing your site. This information helps optimize website compatibility, track mobile versus desktop usage trends, and identify outdated browser versions requiring support. Understanding browser patterns is essential for delivering optimal user experiences across different platforms.

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

Monitor and analyze automated traffic patterns across your nginx server. This query helps distinguish between legitimate bot traffic (such as search engine crawlers) and potentially malicious automated access. Understanding bot behavior patterns is crucial for managing server resources and maintaining security.

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

Identify potentially malicious or suspicious requests targeting your server. This query detects common attack patterns, unauthorized access attempts, and potential security vulnerabilities by monitoring request patterns and payload characteristics. Early detection of security threats is essential for maintaining system integrity and protecting sensitive resources.

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

Detect aggressive request patterns that might indicate abuse or denial of service attempts. This query helps identify potential DDoS attacks, aggressive crawlers, or brute force attempts by monitoring request frequency and patterns from individual IP addresses. Understanding request patterns is crucial for implementing effective rate limiting policies.

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

Monitor backend server performance and response time patterns. This analysis helps identify potential bottlenecks, verify service level agreement compliance, and ensure optimal load balancing across upstream servers. Understanding upstream response patterns is essential for maintaining high-performance web services.

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

Analyze SSL/TLS protocol and cipher usage across your web traffic. This query helps monitor encryption protocol adoption, identify outdated or insecure protocols, and ensure compliance with security standards. Understanding SSL/TLS usage patterns is crucial for maintaining robust security while ensuring broad client compatibility.

```sql
select
  ssl_protocol,
  ssl_cipher,
  count(*) as connection_count,
  round(count(*) * 100.0 / sum(count(*)) over (), 3) as percentage
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

Detect usage of deprecated or insecure SSL ciphers in your web traffic. This query identifies potential security risks by monitoring the use of outdated SSL/TLS protocols and weak cipher suites, helping maintain a strong security posture and ensure compliance with modern encryption standards. Understanding cipher usage patterns is essential for protecting sensitive data and maintaining client trust.

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

Monitor and analyze unusual HTTP method usage across your web traffic. This query helps identify potentially dangerous or non-standard HTTP methods that could indicate attempted exploits, security scanning tools, or misconfigured clients. Understanding HTTP method patterns is crucial for maintaining proper access controls and preventing unauthorized operations.

```sql
select
  request_method,
  count(*) as request_count
from
  nginx_access_log
where
  request_method not in ('GET', 'POST', 'HEAD', 'OPTIONS')
group by
  request_method
order by
  request_count desc;
```

### Failed Authentication Attempts

Track failed authentication attempts across your nginx server. This query helps identify potential brute force attacks or credential stuffing attempts by monitoring patterns of 401 status codes from specific IP addresses. Understanding authentication failure patterns is essential for protecting access to restricted resources and maintaining system security.

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

Monitor requests with unusually large or small response sizes. This query helps identify potential data exfiltration attempts, failed attacks, or misconfigured services by detecting responses that deviate significantly from normal size ranges. Understanding response size patterns is crucial for maintaining proper data transfer controls and preventing unauthorized data access.

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

Analyze requests with potentially malicious or suspicious user agent strings. This query helps identify automated tools, security scanners, and potential attack attempts by monitoring user agent patterns. Understanding user agent characteristics is essential for distinguishing between legitimate clients and potentially harmful automated access.

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

Monitor sudden increases in error rates across your web traffic. This query helps identify potential attacks, system issues, or service degradation by detecting periods where error rates exceed normal thresholds. Understanding error rate patterns is crucial for maintaining service reliability and responding quickly to potential incidents.

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

Monitor potential directory traversal attack attempts targeting your server. This query helps identify malicious requests trying to access sensitive files or directories through path manipulation techniques. Understanding these attack patterns is essential for protecting file system integrity and preventing unauthorized access to restricted resources.

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
  -- Plain directory traversal attempts
  request_uri like '%../%'
  or request_uri like '%/../%'
  or request_uri like '%/./%'
  or request_uri like '%...%'
  or request_uri like '%\\..\\%'
  -- URL-encoded variants (both cases)
  or request_uri like '%..%2f%'
  or request_uri like '%..%2F%'
  or request_uri like '%%2e%2e%2f%'
  or request_uri like '%%2E%2E%2F%'
  or request_uri like '%%2e%2e/%'
  or request_uri like '%%2E%2E/%'
  -- Double-encoded variants
  or request_uri like '%25%32%65%25%32%65%25%32%66%'
  -- Backslash variants
  or request_uri like '%5c..%5c%'
  or request_uri like '%5C..%5C%'
  or request_uri like '%%5c..%5c%'
  or request_uri like '%%5C..%5C%'
order by
  tp_timestamp desc;
```

### SQL Injection Attempts

Monitor potential SQL injection attack attempts against your web applications. This query helps identify malicious requests containing SQL syntax patterns that could indicate attempts to manipulate or extract data from backend databases. Understanding SQL injection patterns is crucial for protecting data integrity and preventing unauthorized database access.

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
  or request_uri like '%''=''%'
order by
  tp_timestamp desc;
```

### Geographic Anomalies

Analyze request patterns based on client IP address ranges to identify geographic access anomalies. This query helps detect requests from unusual locations or known problematic regions, aiding in the identification of potential security threats and traffic patterns that may require additional scrutiny or access controls.

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