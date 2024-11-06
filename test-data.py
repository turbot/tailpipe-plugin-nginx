import random
from datetime import datetime, timedelta
import ipaddress
import numpy as np

def generate_nginx_logs(num_lines=1000, start_date=datetime(2024, 11, 1)):
    # Common HTTP status codes with weighted probability
    status_codes = [200, 301, 302, 304, 400, 403, 404, 500, 502, 503]
    status_weights = [0.75, 0.05, 0.05, 0.05, 0.02, 0.02, 0.03, 0.01, 0.01, 0.01]
    
    # Common user agents
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 16_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1',
        'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36'
    ]
    
    # Common HTTP methods with weighted probability
    methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD']
    method_weights = [0.8, 0.15, 0.02, 0.02, 0.01]
    
    # Common URLs
    urls = [
        '/', 
        '/api/v1/users',
        '/api/v1/products',
        '/about',
        '/contact',
        '/login',
        '/logout',
        '/dashboard',
        '/profile',
        '/static/main.css',
        '/static/main.js',
        '/images/logo.png',
        '/blog',
        '/blog/post-1',
        '/blog/post-2',
        '/favicon.ico'
    ]
    
    # Server names
    server_names = ['web-01.example.com', 'web-02.example.com', 'web-03.example.com']
    
    # Generate realistic looking IPs
    def generate_ip():
        # Generate more IPs in certain subnets to simulate real traffic patterns
        subnets = [
            ipaddress.IPv4Network('10.0.0.0/8'),     # Internal network
            ipaddress.IPv4Network('172.16.0.0/12'),  # Internal network
            ipaddress.IPv4Network('192.168.0.0/16'), # Internal network
            ipaddress.IPv4Network('203.0.113.0/24'), # Documentation/test network
        ]
        
        if random.random() < 0.3:  # 30% chance of internal IP
            subnet = random.choice(subnets)
            network_int = int(subnet.network_address)
            broadcast_int = int(subnet.broadcast_address)
            ip_int = random.randint(network_int, broadcast_int)
            return str(ipaddress.IPv4Address(ip_int))
        else:  # Public IP
            return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}"

    # Generate log lines
    logs = []
    current_time = start_date
    
    for _ in range(num_lines):
        ip = generate_ip()
        timestamp = current_time.strftime('%d/%b/%Y:%H:%M:%S +0000')
        method = random.choices(methods, weights=method_weights)[0]
        url = random.choice(urls)
        status = random.choices(status_codes, weights=status_weights)[0]
        bytes_sent = random.randint(200, 15000) if status != 304 else 0
        referer = '-'
        user_agent = random.choice(user_agents)
        server_name = random.choice(server_names)
        
        # Format: remote_addr - remote_user [timestamp] "request" status bytes_sent "referer" "user_agent"
        log_line = f'{ip} - - [{timestamp}] "{method} {url} HTTP/1.1" {status} {bytes_sent} "{referer}" "{user_agent}" {server_name}'
        logs.append(log_line)
        
        # Increment time randomly between 1 and 10 seconds
        current_time += timedelta(seconds=random.randint(1, 10))
    
    return logs

# Generate and print logs
logs = generate_nginx_logs()
print('\n'.join(logs))