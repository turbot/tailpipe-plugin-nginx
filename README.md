# tailpipe-plugin-nginx

Tailpipe plugin to collect and query nginx logs.

## Analyze Traffic by Server

```sql
SELECT
    tp_index as server,
    count(*) as requests,
    count(distinct remote_addr) as unique_ips,
    round(avg(bytes_sent)) as avg_bytes,
    count(CASE WHEN status = 200 THEN 1 END) as success_count,
    count(CASE WHEN status >= 500 THEN 1 END) as error_count,
    round(avg(CASE WHEN method = 'GET' THEN bytes_sent END)) as avg_get_bytes
FROM nginx_access_log
WHERE tp_date = '2024-11-01'
GROUP BY tp_index
ORDER BY requests DESC;
```

```
┌──────────────────────────────────────────────────────────────────────────────────────┐
│ server      requests    unique_ips  avg_bytes   success_c…  error_cou…  avg_get_b…   │
│────────────────────────────────────────────────────────────────────────────────────  │
│ web-01.ex…  349         346         7036        267         7           7158        │
│ web-02.ex…  327         327         6792        246         11          6815        │
│ web-03.ex…  324         322         7001        254         8           6855        │
└──────────────────────────────────────────────────────────────────────────────────────┘
```

### Time-Oriented Query

```sql
SELECT
    tp_date,
    tp_index as server,
    remote_addr as ip,
    method,
    uri,
    status,
    bytes_sent
FROM nginx_access_log
WHERE tp_date = '2024-11-01'
LIMIT 10;
```

```
+--------------------------------------------------------------------------------------+
¦ tp_date      server           ip             method  uri             status  bytes_sent¦
¦------------------------------------------------------------------------------------  ¦
¦ 2024-11-01   web-01.example  220.50.48.32   GET     /profile/user  200     5704     ¦
¦ 2024-11-01   web-01.example  10.166.12.45   GET     /blog/post/1   200     2341     ¦
¦ 2024-11-01   web-01.example  203.0.113.10   GET     /dashboard     200     11229    ¦
¦ 2024-11-01   web-01.example  45.211.16.72   PUT     /favicon.ico   301     2770     ¦
¦ 2024-11-01   web-01.example  66.171.35.91   POST    /static/main   503     5928     ¦
¦ 2024-11-01   web-01.example  64.152.79.83   GET     /logout        200     3436     ¦
¦ 2024-11-01   web-01.example  156.25.84.12   GET     /static/main   200     12490    ¦
¦ 2024-11-01   web-01.example  78.131.22.45   GET     /static/main   200     8342     ¦
¦ 2024-11-01   web-01.example  203.0.113.10   POST    /api/v1/user   200     3123     ¦
¦ 2024-11-01   web-01.example  10.74.127.93   POST    /              200     7210     ¦
+--------------------------------------------------------------------------------------+
```

[!NOTE] Because we specified `tp_date = '2024-11-01'`, Tailpipe only needs to read the parquet files in the corresponding date directories. Similarly, if you wanted to analyze traffic for a specific server, you could add `tp_index = 'web-01.example.com'` to your WHERE clause, and Tailpipe would only read files from that server's directory.

## Developers

Build a developer version of the plugin:
```
make
```

Check it was created and installed:
```
ls -al ~/.tailpipe/plugins
```
