-- threat1595.sql
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
