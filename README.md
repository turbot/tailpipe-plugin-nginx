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
┌────────────────────┬──────────┬────────────┬───────────┬───────────────┬─────────────┬───────────────┐
│       server       │ requests │ unique_ips │ avg_bytes │ success_count │ error_count │ avg_get_bytes │
│      varchar       │  int64   │   int64    │  double   │     int64     │    int64    │    double     │
├────────────────────┼──────────┼────────────┼───────────┼───────────────┼─────────────┼───────────────┤
│ default            │     2000 │        985 │    6945.0 │          1534 │          52 │        6952.0 │
│ web-01.example.com │      349 │        346 │    7036.0 │           267 │           7 │        7158.0 │
│ web-03.example.com │      328 │        322 │    6934.0 │           258 │           8 │        6769.0 │
│ web-02.example.com │      327 │        327 │    6792.0 │           246 │          11 │        6815.0 │
└────────────────────┴──────────┴────────────┴───────────┴───────────────┴─────────────┴───────────────┘
```

## Time-Oriented Query

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
┌────────────┬─────────┬─────────────────┬─────────┬──────────────────┬────────┬────────────┐
│  tp_date   │ server  │       ip        │ method  │       uri        │ status │ bytes_sent │
│    date    │ varchar │     varchar     │ varchar │     varchar      │ int64  │   int64    │
├────────────┼─────────┼─────────────────┼─────────┼──────────────────┼────────┼────────────┤
│ 2024-11-01 │ default │ 192.29.251.248  │ GET     │ /login           │    200 │      12471 │
│ 2024-11-01 │ default │ 220.50.48.207   │ GET     │ /profile         │    200 │       5704 │
│ 2024-11-01 │ default │ 10.170.192.131  │ DELETE  │ /about           │    301 │      10953 │
│ 2024-11-01 │ default │ 130.169.168.157 │ GET     │ /images/logo.png │    200 │      13526 │
│ 2024-11-01 │ default │ 203.0.113.179   │ GET     │ /static/main.js  │    200 │       4172 │
│ 2024-11-01 │ default │ 10.166.122.8    │ GET     │ /blog/post-2     │    200 │       2341 │
│ 2024-11-01 │ default │ 207.227.205.16  │ GET     │ /login           │    200 │       6661 │
│ 2024-11-01 │ default │ 148.73.73.74    │ GET     │ /dashboard       │    200 │      14361 │
│ 2024-11-01 │ default │ 129.67.64.70    │ POST    │ /login           │    301 │      11282 │
│ 2024-11-01 │ default │ 85.84.30.85     │ GET     │ /                │    404 │       3091 │
├────────────┴─────────┴─────────────────┴─────────┴──────────────────┴────────┴────────────┤
│ 10 rows                                                                         7 columns │
└───────────────────────────────────────────────────────────────────────────────────────────┘
```

[!NOTE] Because we specified `tp_date = '2024-11-01'`, Tailpipe only needs to read the parquet files in the corresponding date directories. Similarly, if you wanted to analyze traffic for a specific server, you could add `tp_index = 'web-01.example.com'` to your WHERE clause, and Tailpipe would only read files from that server's directory.

## Threat hunting

### Top URIs Targeted in Failed Requests - Pattern Analysis of Attack Paths

```
SELECT
      uri,
      COUNT(*) as attempts,
      COUNT(DISTINCT remote_addr) as unique_ips,
      MIN(time_local) as first_seen,
      MAX(time_local) as last_seen,
      array_agg(DISTINCT status) as status_codes
  FROM nginx_access_log
  WHERE status >= 400
  GROUP BY uri
  HAVING COUNT(*) > 5
  ORDER BY attempts DESC
  LIMIT 20;
```

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────────────┬──────────┬────────────┬─────────────────────┬─────────────────────┬────────────────────────────────┐
│                                                   uri                                                    │ attempts │ unique_ips │     first_seen      │      last_seen      │          status_codes          │
│                                                 varchar                                                  │  int64   │   int64    │      timestamp      │      timestamp      │            int64[]             │
├──────────────────────────────────────────────────────────────────────────────────────────────────────────┼──────────┼────────────┼─────────────────────┼─────────────────────┼────────────────────────────────┤
│ /.env                                                                                                    │       30 │          8 │ 2024-11-02 00:49:50 │ 2024-11-02 23:59:17 │ [404]                          │
│ /favicon.ico                                                                                             │       30 │         12 │ 2024-11-01 00:23:06 │ 2024-11-02 23:04:20 │ [404, 403, 500]                │
│ /                                                                                                        │       25 │         11 │ 2024-11-01 00:00:49 │ 2024-11-02 23:59:18 │ [405, 404, 400, 502]           │
│                                                                                                          │       21 │          5 │ 2024-11-02 04:25:25 │ 2024-11-02 14:21:00 │ [400]                          │
│ /login.rsp                                                                                               │       15 │          2 │ 2024-11-02 00:34:11 │ 2024-11-02 23:24:09 │ [404]                          │
│ /api/v1/products                                                                                         │       14 │          7 │ 2024-11-01 00:15:20 │ 2024-11-01 01:29:09 │ [403, 502, 400, 404]           │
│ /logout                                                                                                  │       14 │          7 │ 2024-11-01 00:05:33 │ 2024-11-01 01:25:43 │ [403, 404, 400, 502]           │
│ /about                                                                                                   │       14 │          7 │ 2024-11-01 00:03:26 │ 2024-11-01 01:25:24 │ [404, 400, 500, 403]           │
│ /static/main.css                                                                                         │       14 │          7 │ 2024-11-01 00:11:09 │ 2024-11-01 01:19:29 │ [500, 403, 400, 404, 502, 503] │
│ /dashboard                                                                                               │       12 │          6 │ 2024-11-01 00:06:05 │ 2024-11-01 01:20:36 │ [403, 503, 404]                │
│ \x84\xB4,\x85\xAFn\xE3Y\xBBbhl\xFF(=':\xA9\x82\xD9o\xC8\xA2\xD7\x93\x98\xB4\xEF\x80\xE5\xB9\x90\x00(\xC0 │       12 │          3 │ 2024-11-02 02:22:34 │ 2024-11-02 20:19:44 │ [400]                          │
│ /backend/express/v1/deployment.yaml                                                                      │       12 │          1 │ 2024-11-02 19:29:29 │ 2024-11-02 19:36:45 │ [404]                          │
│ /login                                                                                                   │       12 │          6 │ 2024-11-01 00:19:36 │ 2024-11-01 00:52:40 │ [503, 404, 502, 403]           │
│ /config/aws/prod/config.json                                                                             │       12 │          1 │ 2024-11-02 19:29:28 │ 2024-11-02 19:36:44 │ [404]                          │
│ /data/etl_jobs/v1/index.js                                                                               │       12 │          1 │ 2024-11-02 19:29:28 │ 2024-11-02 19:36:44 │ [404]                          │
│ /static/main.js                                                                                          │       12 │          6 │ 2024-11-01 00:01:55 │ 2024-11-01 00:57:20 │ [503, 400, 403]                │
│ /data/etl_jobs/v2/requirements.txt                                                                       │       12 │          1 │ 2024-11-02 19:29:29 │ 2024-11-02 19:36:45 │ [404]                          │
│ /microservices/user-service/prod/Dockerfile                                                              │       12 │          1 │ 2024-11-02 19:29:29 │ 2024-11-02 19:36:45 │ [404]                          │
│ /backend/fastapi/src/swagger.json                                                                        │       12 │          1 │ 2024-11-02 19:29:29 │ 2024-11-02 19:36:45 │ [404]                          │
│ /frontend/svelte-app/dev/deployment.yaml                                                                 │       12 │          1 │ 2024-11-02 19:29:30 │ 2024-11-02 19:36:46 │ [404]                          │
├──────────────────────────────────────────────────────────────────────────────────────────────────────────┴──────────┴────────────┴─────────────────────┴─────────────────────┴────────────────────────────────┤
```


###  Failed Request Analysis by Individual IP - Shows scanning activity per unique address

```
SELECT
      regexp_extract(remote_addr, '^(\d+\.\d+\.\d+\.\d+)') as ip_range,
      COUNT(DISTINCT remote_addr) as unique_ips,
      COUNT(*) as total_attempts,
      COUNT(DISTINCT uri) as unique_paths
  FROM nginx_access_log
  WHERE status >= 400
  GROUP BY regexp_extract(remote_addr, '^(\d+\.\d+\.\d+\.\d+)')
  HAVING COUNT(*) > 10
  ORDER BY total_attempts DESC;
```

```
┌────────────────┬────────────┬────────────────┬──────────────┐
│    ip_range    │ unique_ips │ total_attempts │ unique_paths │
│    varchar     │   int64    │     int64      │    int64     │
├────────────────┼────────────┼────────────────┼──────────────┤
│ 94.72.101.21   │          1 │          37377 │        12126 │
│ 112.254.36.175 │          1 │            135 │           45 │
│ 136.144.19.42  │          1 │            102 │           17 │
│ 136.144.19.175 │          1 │             78 │           13 │
│ 148.153.45.238 │          1 │             18 │            6 │
│ 123.58.207.127 │          1 │             15 │            5 │
│ 178.215.238.68 │          1 │             12 │            1 │
│ 71.6.146.130   │          1 │             12 │            4 │
└────────────────┴────────────┴────────────────┴──────────────┘
```

###  Path Analysis for Major Scanner 94.72.101.21 - Attack Pattern Investigation

```
SELECT
      uri,
      COUNT(*) as attempts,
      MIN(time_local) as first_seen,
      MAX(time_local) as last_seen,
      array_agg(DISTINCT status) as status_codes,
      array_agg(DISTINCT method) as methods_used
  FROM nginx_access_log
  WHERE remote_addr = '94.72.101.21'
  GROUP BY uri
  ORDER BY attempts DESC
  LIMIT 20;
  ```

```
┌─────────────────────────────────────────────┬──────────┬─────────────────────┬─────────────────────┬──────────────┬──────────────┐
│                     uri                     │ attempts │     first_seen      │      last_seen      │ status_codes │ methods_used │
│                   varchar                   │  int64   │      timestamp      │      timestamp      │   int64[]    │  varchar[]   │
├─────────────────────────────────────────────┼──────────┼─────────────────────┼─────────────────────┼──────────────┼──────────────┤
│ /data/etl_jobs/v2/requirements.txt          │       12 │ 2024-11-02 19:29:29 │ 2024-11-02 19:36:45 │ [404]        │ [GET]        │
│ /microservices/user-service/prod/Dockerfile │       12 │ 2024-11-02 19:29:29 │ 2024-11-02 19:36:45 │ [404]        │ [GET]        │
│ /backend/fastapi/src/swagger.json           │       12 │ 2024-11-02 19:29:29 │ 2024-11-02 19:36:45 │ [404]        │ [GET]        │
│ /frontend/svelte-app/dev/deployment.yaml    │       12 │ 2024-11-02 19:29:30 │ 2024-11-02 19:36:46 │ [404]        │ [GET]        │
│ /config/database/src/Dockerfile             │       12 │ 2024-11-02 19:29:28 │ 2024-11-02 19:36:43 │ [404]        │ [GET]        │
│ /audit/logs/v1/setup.py                     │       12 │ 2024-11-02 19:29:30 │ 2024-11-02 19:36:46 │ [404]        │ [GET]        │
│ /config/aws/prod/config.json                │       12 │ 2024-11-02 19:29:28 │ 2024-11-02 19:36:44 │ [404]        │ [GET]        │
│ /data/etl_jobs/v1/index.js                  │       12 │ 2024-11-02 19:29:28 │ 2024-11-02 19:36:44 │ [404]        │ [GET]        │
│ /backend/express/v1/deployment.yaml         │       12 │ 2024-11-02 19:29:29 │ 2024-11-02 19:36:45 │ [404]        │ [GET]        │
│ /compliance/reports/dev/main.js             │       12 │ 2024-11-02 19:29:29 │ 2024-11-02 19:36:44 │ [404]        │ [GET]        │
│ /config/azure/dist/service.yaml             │       12 │ 2024-11-02 19:29:30 │ 2024-11-02 19:36:46 │ [404]        │ [GET]        │
│ /config/env/prod/Dockerfile                 │        9 │ 2024-11-02 19:29:32 │ 2024-11-02 19:36:48 │ [404]        │ [GET]        │
│ /terraform/environments/prod/src/schema.sql │        9 │ 2024-11-02 19:29:34 │ 2024-11-02 19:36:51 │ [404]        │ [GET]        │
│ /config/aws/dev/swagger.json                │        9 │ 2024-11-02 19:29:35 │ 2024-11-02 19:36:52 │ [404]        │ [GET]        │
│ /microservices/inventory/v1/app.py          │        9 │ 2024-11-02 19:29:36 │ 2024-11-02 19:36:52 │ [404]        │ [GET]        │
│ /ml/models/prod/setup.py                    │        9 │ 2024-11-02 19:29:31 │ 2024-11-02 19:36:47 │ [404]        │ [GET]        │
│ /data_sources/dist/requirements.txt         │        9 │ 2024-11-02 19:29:32 │ 2024-11-02 19:36:48 │ [404]        │ [GET]        │
│ /ci-cd/gitlab/v1/secrets.env                │        9 │ 2024-11-02 19:29:33 │ 2024-11-02 19:36:48 │ [404]        │ [GET]        │
│ /docs/readme/v2/.env                        │        9 │ 2024-11-02 19:29:31 │ 2024-11-02 19:36:46 │ [404]        │ [GET]        │
│ /frontend/react-app/dev/schema.sql          │        9 │ 2024-11-02 19:29:35 │ 2024-11-02 19:36:52 │ [404]        │ [GET]        │
├─────────────────────────────────────────────┴──────────┴─────────────────────┴─────────────────────┴──────────────┴──────────────┤
```

The scanner is methodically looking for files that could reveal:

- Cloud credentials
- Database schemas
- Application architecture
- Internal APIs
- Development secrets
- Infrastructure details

###  Attacker Reconnaissance Categories - Sensitive Resource Targeting Analysis

```
SELECT
     CASE
         WHEN uri LIKE '%/aws/%' OR uri LIKE '%/azure/%' OR uri LIKE '%.env' OR uri LIKE '%secrets%'
             THEN 'Cloud/Credentials Hunting'
         WHEN uri LIKE '%/database/%' OR uri LIKE '%schema.sql%' OR uri LIKE '%etl%'
             THEN 'Database/Data Access'
         WHEN uri LIKE '%swagger%' OR uri LIKE '%fastapi%' OR uri LIKE '%express%' OR uri LIKE '%microservices%'
             THEN 'API/Service Discovery'
         WHEN uri LIKE '%Dockerfile%' OR uri LIKE '%deployment%' OR uri LIKE '%terraform%'
             THEN 'Infrastructure/Deployment'
         WHEN uri LIKE '%audit%' OR uri LIKE '%compliance%' OR uri LIKE '%logs%'
             THEN 'Security/Compliance'
         WHEN uri LIKE '%/src/%' OR uri LIKE '%/dev/%' OR uri LIKE '%setup.py%' OR uri LIKE '%index.js%'
             THEN 'Source Code'
         ELSE 'Other'
     END as recon_category,
     COUNT(*) as attempts,
     COUNT(DISTINCT uri) as unique_paths,
     array_agg(DISTINCT uri) as paths_tried,
     MIN(time_local) as first_attempt,
     MAX(time_local) as last_attempt
  FROM nginx_access_log
  WHERE remote_addr = '94.72.101.21'
   AND status = 404  -- Looking specifically for their probing attempts
  GROUP BY 1
  ORDER BY attempts DESC;
  ```

  ```
┌──────────────────────┬──────────┬──────────────┬───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┬─────────────────────┬─────────────────────┐
│    recon_category    │ attempts │ unique_paths │                                                      paths_tried                                                      │    first_attempt    │    last_attempt     │
│       varchar        │  int64   │    int64     │                                                       varchar[]                                                       │      timestamp      │      timestamp      │
├──────────────────────┼──────────┼──────────────┼───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┼─────────────────────┼─────────────────────┤
│ Other                │    21219 │         7010 │ [/product/backend/phpinfo.php, /product/develop/phpinfo.php, /product/service/phpinfo.php, /product/services/info.p…  │ 2024-11-02 19:29:32 │ 2024-11-02 20:29:40 │
│ Cloud/Credentials …  │     7992 │         2597 │ [/config/azure/dist/service.yaml, /data/etl_jobs/dist/secrets.env, /secrets/src/secrets.env, /ci-cd/gitlab/dist/sec…  │ 2024-11-02 19:29:28 │ 2024-11-02 20:29:43 │
│ Source Code          │     3420 │         1090 │ [/product/dev/phpinfo.php, /product/dev/info.php, /services/dev/phpinfo.php, /stg/dev/phpinfo.php, /tests/dev/info.…  │ 2024-11-02 19:29:31 │ 2024-11-02 20:26:44 │
│ API/Service Discov…  │     1662 │          502 │ [/backend/fastapi/prod/index.js, /backend/fastapi/v1/app.py, /backend/express/prod/requirements.txt, /microservices…  │ 2024-11-02 19:29:29 │ 2024-11-02 19:48:59 │
│ Infrastructure/Dep…  │     1542 │          478 │ [/frontend/vue-app/src/deployment.yaml, /frontend/svelte-app/src/Dockerfile, /ci-cd/github/dist/Dockerfile, /audit/…  │ 2024-11-02 19:29:30 │ 2024-11-02 20:16:01 │
│ Database/Data Access │     1080 │          315 │ [/config/database/v1/Dockerfile, /integrations/stripe/dev/schema.sql, /config/database/src/app.py, /config/database…  │ 2024-11-02 19:29:28 │ 2024-11-02 20:29:28 │
│ Security/Compliance  │      462 │          134 │ [/logs/error_log, /compliance/reports/v1/index.js, /compliance/reports/prod/setup.py, /audit/logs/src/setup.py, /au…  │ 2024-11-02 19:29:29 │ 2024-11-02 20:29:22 │
└──────────────────────┴──────────┴──────────────┴───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┴─────────────────────┴─────────────────────┘
```

### Mitre-oriented query

```
-- t1595.log generated from 1595.py
-- MITRE ATT&CK: T1595 Active Scanning
-- Detects systematic scanning activity through multiple indicators:
-- 1. Known scanning tools
-- 2. High-frequency requests from single IPs
-- 3. Common vulnerability probe paths
-- 4. Pattern of sequential scanning behavior

WITH scanner_metrics AS (
    SELECT 
        remote_addr,
        COUNT(*) as total_requests,
        COUNT(DISTINCT uri) as unique_paths,
        array_agg(DISTINCT user_agent) as user_agents,
        array_agg(DISTINCT uri) as paths_tried,
        COUNT(CASE WHEN status >= 400 THEN 1 END)::float / COUNT(*) as error_rate,
        COUNT(CASE WHEN user_agent LIKE '%zgrab%' 
                OR user_agent LIKE '%Nuclei%'
                OR user_agent LIKE '%Nmap%'
                OR user_agent LIKE '%CensysInspect%'
                OR user_agent LIKE '%Expanse%'
                THEN 1 END) as scanner_ua_count,
        COUNT(CASE WHEN uri LIKE '%phpinfo%'
                OR uri LIKE '%_profiler%'
                OR uri LIKE '%.git%'
                OR uri LIKE '%.env%'
                OR uri LIKE '%wp-%'
                OR uri LIKE '%admin%'
                THEN 1 END) as probe_path_count,
        MIN(time_local) as first_seen,
        MAX(time_local) as last_seen,
        EXTRACT(EPOCH FROM (MAX(time_local) - MIN(time_local))) as time_span_seconds
    FROM nginx_access_log
    GROUP BY remote_addr
    HAVING COUNT(*) > 5  -- Minimum activity threshold
)
SELECT 
    remote_addr,
    total_requests,
    unique_paths,
    ROUND(error_rate * 100, 2) as error_rate_pct,
    scanner_ua_count,
    probe_path_count,
    ROUND(total_requests::float / NULLIF(time_span_seconds, 0), 3) as requests_per_second,
    first_seen,
    last_seen,
    -- Classification based on multiple indicators
    CASE 
        WHEN scanner_ua_count > 0 
          OR (error_rate > 0.4 AND probe_path_count > 0)
          OR (total_requests::float / NULLIF(time_span_seconds, 0) > 0.5 AND unique_paths > 5)
        THEN 'HIGH'
        WHEN error_rate > 0.2 
          OR probe_path_count > 0
          OR unique_paths > 10
        THEN 'MEDIUM'
        ELSE 'LOW'
    END as threat_level,
    user_agents,
    paths_tried
FROM scanner_metrics
WHERE 
    scanner_ua_count > 0
    OR probe_path_count > 0
    OR error_rate > 0.2
    OR (total_requests::float / NULLIF(time_span_seconds, 0) > 0.2 AND unique_paths > 5)
ORDER BY 
    CASE threat_level 
        WHEN 'HIGH' THEN 1 
        WHEN 'MEDIUM' THEN 2 
        ELSE 3 
    END,
    total_requests DESC
LIMIT 25;
```

```
┌────────────────┬────────────────┬──────────────┬────────────────┬──────────────────┬──────────────────┬─────────────────────┬─────────────────────┬─────────────────────┬──────────────┬──────────────────────┬────────────────────────────────────────┐
│  remote_addr   │ total_requests │ unique_paths │ error_rate_pct │ scanner_ua_count │ probe_path_count │ requests_per_second │     first_seen      │      last_seen      │ threat_level │     user_agents      │              paths_tried               │
│    varchar     │     int64      │    int64     │     float      │      int64       │      int64       │       double        │      timestamp      │      timestamp      │   varchar    │      varchar[]       │               varchar[]                │
├────────────────┼────────────────┼──────────────┼────────────────┼──────────────────┼──────────────────┼─────────────────────┼─────────────────────┼─────────────────────┼──────────────┼──────────────────────┼────────────────────────────────────────┤
│ 94.72.101.21   │          49836 │        12126 │          100.0 │                0 │            19428 │              13.786 │ 2024-11-02 19:29:28 │ 2024-11-02 20:29:43 │ HIGH         │ [Mozilla/5.0 (Maci…  │ [/product/.env.production, /project/…  │
│ 236.136.121.59 │            217 │           10 │          72.35 │              217 │              112 │               0.001 │ 2024-11-01 00:05:20 │ 2024-11-02 20:11:33 │ HIGH         │ [Mozilla/5.0 (comp…  │ [/.git/config, /api/swagger, /actuat…  │
│ 237.64.63.208  │            214 │           10 │          71.03 │              214 │              100 │               0.001 │ 2024-11-01 00:12:34 │ 2024-11-02 19:36:50 │ HIGH         │ [Mozilla/5.0 (comp…  │ [/server-status, /.well-known/securi…  │
│ 79.154.38.75   │            202 │           10 │          74.26 │              202 │               96 │               0.001 │ 2024-11-01 00:05:23 │ 2024-11-02 19:53:26 │ HIGH         │ [Expanse, a Palo A…  │ [/server-status, /.well-known/securi…  │
│ 189.182.230.22 │            198 │           10 │          72.73 │              198 │               89 │               0.001 │ 2024-11-01 00:02:00 │ 2024-11-02 19:55:56 │ HIGH         │ [Mozilla/5.0 (comp…  │ [/.env, /phpinfo.php, /actuator/heal…  │
│ 32.20.221.188  │            193 │           10 │          75.13 │              193 │               93 │               0.001 │ 2024-11-01 00:39:00 │ 2024-11-02 19:56:52 │ HIGH         │ [Mozilla/5.0 (comp…  │ [/admin, /.well-known/security.txt, …  │
│ 112.254.36.175 │            180 │           45 │          100.0 │                0 │                4 │                20.0 │ 2024-11-02 15:17:01 │ 2024-11-02 15:17:10 │ HIGH         │ [Custom-AsyncHttpC…  │ [/phpunit/src/Util/PHP/eval-stdin.ph…  │
│ 136.144.19.42  │            140 │           18 │          97.14 │                0 │              112 │                3.59 │ 2024-11-02 19:18:31 │ 2024-11-02 19:19:10 │ HIGH         │ [Mozilla/5.0 (X11;…  │ [/, /.aws/config, /.env, /services/c…  │
│ 136.144.19.175 │            104 │           13 │          100.0 │                0 │              104 │               2.476 │ 2024-11-02 19:19:50 │ 2024-11-02 19:20:32 │ HIGH         │ [Mozilla/5.0 (X11;…  │ [/system/.env, /environment/.env, /e…  │
│ 123.58.207.127 │             24 │            6 │          83.33 │                0 │                0 │               0.828 │ 2024-11-02 14:21:00 │ 2024-11-02 14:21:29 │ HIGH         │ [Mozilla/5.0 (Maci…  │ [/favicon.ico, , /, /sitemap.xml, /c…  │
│ 167.94.145.109 │             16 │            3 │           50.0 │                8 │                0 │                 3.2 │ 2024-11-02 01:18:23 │ 2024-11-02 01:18:28 │ HIGH         │ [-, Mozilla/5.0 (c…  │ [/favicon.ico, *, /]                   │
│ 167.94.138.50  │             16 │            3 │           50.0 │                8 │                0 │               1.143 │ 2024-11-02 21:06:23 │ 2024-11-02 21:06:37 │ HIGH         │ [Mozilla/5.0 (comp…  │ [*, /, /favicon.ico]                   │
│ 45.140.188.18  │              8 │            2 │          100.0 │                0 │                4 │                     │ 2024-11-02 10:39:55 │ 2024-11-02 10:39:55 │ HIGH         │ [Mozilla/5.0 (X11;…  │ [, /boaform/admin/formLogin]           │
│ 87.120.113.56  │              8 │            1 │          100.0 │                0 │                8 │                 0.0 │ 2024-11-02 09:06:11 │ 2024-11-02 22:48:41 │ HIGH         │ [Mozilla/5.0 (Maci…  │ [/.env]                                │
│ 178.159.37.59  │              8 │            2 │          100.0 │                0 │                8 │               0.001 │ 2024-11-02 00:49:50 │ 2024-11-02 02:35:43 │ HIGH         │ [Mozilla/5.0 (Maci…  │ [/.gitlab-ci.yml, /.env]               │
│ 103.145.255.68 │              8 │            2 │          100.0 │                0 │                4 │                 8.0 │ 2024-11-02 23:59:17 │ 2024-11-02 23:59:18 │ HIGH         │ [Mozilla/5.0 (X11;…  │ [/, /.env]                             │
│ 141.98.11.178  │             28 │            2 │          42.86 │                0 │                0 │               0.001 │ 2024-11-02 12:31:47 │ 2024-11-02 22:33:13 │ MEDIUM       │ [Go-http-client/1.…  │ [/cgi-bin/luci/;stok=/locale, /]       │
│ 198.44.237.38  │             24 │            3 │           50.0 │                0 │                0 │               0.001 │ 2024-11-02 03:05:27 │ 2024-11-02 08:29:14 │ MEDIUM       │ [Mozilla/5.0 (Wind…  │ [5\xD5\xD1n\x8E`>7DQ\x0FC\xFD5\xF4\x…  │
│ 148.153.45.238 │             24 │            6 │          100.0 │                0 │                0 │                     │ 2024-11-02 06:52:23 │ 2024-11-02 06:52:23 │ MEDIUM       │ [Mozilla/5.0 (Maci…  │ [/NJKz, /aab9, /jquery-3.3.1.slim.mi…  │
│ 71.6.146.130   │             20 │            5 │           80.0 │                0 │                0 │               6.667 │ 2024-11-02 23:04:17 │ 2024-11-02 23:04:20 │ MEDIUM       │ [Mozilla/5.0 (Wind…  │ [/favicon.ico, /, /sitemap.xml, /.we…  │
│ 5.8.11.202     │             16 │            2 │           25.0 │                0 │                0 │                 0.0 │ 2024-11-02 06:03:57 │ 2024-11-02 21:40:27 │ MEDIUM       │ [Mozilla/5.0 (Wind…  │ [\x84\xB4,\x85\xAFn\xE3Y\xBBbhl\xFF(…  │
│ 178.215.238.68 │             16 │            1 │          100.0 │                0 │                0 │                 0.0 │ 2024-11-02 00:34:11 │ 2024-11-02 23:24:09 │ MEDIUM       │ [Hello World]        │ [/login.rsp]                           │
│ 93.174.93.12   │             16 │            2 │           50.0 │                0 │                0 │                 0.0 │ 2024-11-02 02:22:34 │ 2024-11-02 22:46:03 │ MEDIUM       │ [-, Mozilla/5.0 (X…  │ [\x84\xB4,\x85\xAFn\xE3Y\xBBbhl\xFF(…  │
│ 203.0.113.175  │             12 │            6 │          33.33 │                0 │                0 │               0.003 │ 2024-11-01 00:13:02 │ 2024-11-01 01:21:41 │ MEDIUM       │ [Mozilla/5.0 (Wind…  │ [/favicon.ico, /login, /dashboard, /…  │
│ 80.82.77.202   │             12 │            2 │          33.33 │                0 │                0 │                 0.0 │ 2024-11-02 05:17:06 │ 2024-11-02 21:26:59 │ MEDIUM       │ [Mozilla/5.0 (iPho…  │ [\x84\xB4,\x85\xAFn\xE3Y\xBBbhl\xFF(…  │
├────────────────┴────────────────┴──────────────┴────────────────┴──────────────────┴──────────────────┴─────────────────────┴─────────────────────┴─────────────────────┴──────────────┴──────────────────────┴────────────────────────────────────────┤
```


## Developers

Build a developer version of the plugin:
```
make
```

Check it was created and installed:
```
ls -al ~/.tailpipe/plugins
```
