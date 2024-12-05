# Table: Nginx Access Log - Query nginx logs using SQL

nginx is a high-performance, open-source web server and reverse proxy server designed for efficiency, scalability, and reliability. 

## Table Usage Guide

### Collection

To collect query logs from a server, your `~/tailpipe/config/nginx.tpc` might look like this.

```hcl
 partition "nginx_access_log" "dev" {
    source "file_system"  {
        paths = [
          "/path/to/logs/dev1"
          ]
        extensions = [".log", ".1", ".gz"]
    }
}
```

Your collection command would be:

```
tailpipe collect nginx_access_logs.dev
```

You can then use tailpipe (or DuckDB) to query the table `nginx_access_log`.

To add another server, you could add a path to the `paths` array. To create another multi-server partition, you could add a `prod` partition.

#### Querying generated test data

As an alternative to collection, you can generate test data that includes threat patterns that may not exist in your logs. The [tests](../../tests) folder includes a sample generator. To run it, then query the generated data:

```
python generate.py
duckdb
CREATE VIEW nginx_access_log AS SELECT * FROM read_parquet('nginx_access_log.parquet');
```
## Query Examples

### logshell exploitation

```sql
select
    tp_source_ip,
    http_user_agent,
    count(*) as attempt_count,
    min(timestamp) as first_seen,
    max(timestamp) as last_seen,
    string_agg(request_details->>'path', ' | ') as sample_paths
from nginx_access_log
where request_details->>'path' like '%${jndi:ldap://%'
group by tp_source_ip, http_user_agent
having count(*) > 2
order by attempt_count desc;
```

### Path traversal and sensitive file access attempts from known bad IPs

```sql
with suspicious_ips as (
    select tp_source_ip, count(*) as suspicious_count
    from nginx_access_log
    where
        request_details.path like '%/../%' 
        or request_details.path like '%/.git/%'
        or request_details.path like '%/.env%'
        or request_details.path like '%/wp-config%'
    group by tp_source_ip
    having count(*) > 2
)
select
    l.tp_source_ip,
    l.http_user_agent,
    count(*) as total_requests,
    count(distinct request_details.path) as unique_paths,
    string_agg(distinct request_details.path, ' | ') as paths,
    min(l.timestamp) as first_seen,
    max(l.timestamp) as last_seen,
    -- Add new details about the requests
    array_agg(distinct request_details.method) as methods_used,
    array_agg(distinct request_details.extension) filter (where request_details.extension is not null) as file_extensions,
    count(distinct request_details.path_segments) as unique_path_patterns
from nginx_access_log l
join suspicious_ips s on l.tp_source_ip = s.tp_source_ip
group by l.tp_source_ip, l.http_user_agent
order by total_requests desc;
```

### SQL injection

```sql
with sql_injection_patterns as (
    select unnest(array[
        'union select',
        'union all select',
        'union/**/select',
        'select(select',
        'or 1=1',
        'or true',
        'or false',
        'or condition',
        '; drop',
        '; truncate',
        '; delete',
        'sleep(',
        'waitfor delay',
        'benchmark(',
        'pg_sleep',
        '@@version',
        'information_schema',
        'database()',
        'char(',
        'concat(',
        'group_concat(',
        'sql error',
        'syntax error'
    ]) as pattern
)
select distinct
    tp_source_ip,
    http_user_agent,
    request_details.method as http_method,
    request_details.path as path,
    request_details.query_params,
    timestamp
from nginx_access_log
cross join sql_injection_patterns
where 
    -- Check path for SQL injection patterns
    lower(request_details.path) like '%' || lower(pattern) || '%'
    -- Note: Query parameter checking will depend on how you want to handle the struct type
order by timestamp desc;
```

