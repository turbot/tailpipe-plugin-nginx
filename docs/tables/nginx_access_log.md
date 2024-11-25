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
    string_agg(path, ' | ') as sample_paths
from nginx_access_log
where path like '%${jndi:ldap://%'
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
        path like '%/../%' or
        path like '%/.git/%' or
        path like '%/.env%' or
        path like '%/wp-config%'
    group by tp_source_ip
    having count(*) > 2
)
select
    l.tp_source_ip,
    l.http_user_agent,
    count(*) as total_requests,
    count(distinct l.path) as unique_paths,
    string_agg(distinct l.path, ' | ') as paths,
    min(l.timestamp) as first_seen,
    max(l.timestamp) as last_seen
from nginx_access_log l
join suspicious_ips s on l.tp_source_ip = s.tp_source_ip
group by l.tp_source_ip, l.http_user_agent
order by total_requests desc;
```

## SQL injection

```sql
select distinct
      tp_source_ip,
      http_user_agent,
      path
  from nginx_access_log
  where
      path ilike '%union select%' or
      path ilike '%union all select%' or
      path ilike '%union/**/select%' or
      path ilike '%select(select%' or
      path ilike '%or%1=1%' or
      path ilike '%or true%' or
      path ilike '%or false%' or
      path ilike '%or%condition%' or
      path ilike '%; drop%' or
      path ilike '%; truncate%' or
      path ilike '%; delete%' or
      path ilike '%sleep(%' or
      path ilike '%waitfor delay%' or
      path ilike '%benchmark(%' or
      path ilike '%pg_sleep%' or
      path ilike '%@@version%' or
      path ilike '%information_schema%' or
      path ilike '%database()%' or
      path ilike '%char(%' or
      path ilike '%concat(%' or
      path ilike '%group_concat(%' or
      path ilike '%sql%error%' or
      path ilike '%syntax%error%'  ;
```

