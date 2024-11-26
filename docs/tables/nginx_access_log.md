# Access Log Table

> [!NOTE]
> To collect from multiple servers in a partition called `dev` your `nginx.tpc` would look like this.
>git d
> ```
> partition "nginx_access_log" "dev" {
>    source "file_system"  {
>        paths = [
>          "/path/to/logs/dev1",
>          "/path/to/logs/dev2"
>          ]
>        extensions = [".log", ".1", ".gz"]
>    }
>}
>
> You could add another partition, `prod`, in  similar way.

> [!NOTE]
> To run these sample queries against generated test data:
>
> ```
>  cd ../../tests
>  python generate.py
>  duckdb
>  CREATE VIEW nginx_access_log AS SELECT * FROM read_parquet('nginx_access_log.parquet');
> ```

## logshell exploitation

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

## Path traversal and sensitive file access attempts from known bad IPs

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

## SQL injection

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

