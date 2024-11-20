import random
from datetime import datetime, timedelta
import ipaddress

def generate_t1595_log(num_lines=10000, start_date=datetime(2024, 11, 1)):
    # Regular user agents
    normal_user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 16_6_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1'
    ]
    
    # Scanner user agents
    scanner_user_agents = [
        'zgrab/0.x',
        'Nmap Scripting Engine',
        'Mozilla/5.0 (compatible; Nuclei; +https://github.com/projectdiscovery/nuclei)',
        'Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)',
        'Expanse, a Palo Alto Networks company, searches across the global IPv4 space multiple times per day to identify customers'
    ]
    
    # Normal paths
    normal_paths = [
        '/', 
        '/about',
        '/products',
        '/contact',
        '/login',
        '/static/main.css',
        '/static/main.js',
        '/images/logo.png',
        '/api/v1/products',
        '/blog'
    ]
    
    # Scanner paths (vulnerability scanning)
    scanner_paths = [
        '/phpinfo.php',
        '/.env',
        '/wp-admin',
        '/admin',
        '/config.php',
        '/.git/config',
        '/server-status',
        '/actuator/health',
        '/api/swagger',
        '/.well-known/security.txt'
    ]

    # Define scanner IPs that will perform active scanning
    scanner_ips = [
        str(ipaddress.IPv4Address(random.randint(0, 2**32 - 1))) for _ in range(5)
    ]

    logs = []
    current_time = start_date

    # Generate logs
    for _ in range(num_lines):
        # 90% normal traffic, 10% scanner traffic
        is_scanner = random.random() < 0.1
        
        if is_scanner:
            ip = random.choice(scanner_ips)
            user_agent = random.choice(scanner_user_agents)
            path = random.choice(scanner_paths)
            # Scanners tend to make requests more rapidly
            current_time += timedelta(seconds=random.randint(1, 3))
            # Scanners often get 404s or 403s
            status = random.choice([404, 403, 400, 200])
        else:
            ip = str(ipaddress.IPv4Address(random.randint(0, 2**32 - 1)))
            user_agent = random.choice(normal_user_agents)
            path = random.choice(normal_paths)
            current_time += timedelta(seconds=random.randint(5, 30))
            # Normal traffic usually succeeds
            status = random.choice([200, 200, 200, 200, 301, 302, 404])

        # Generate log line in NGINX combined format
        log_line = f'{ip} - - [{current_time.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET {path} HTTP/1.1" {status} {random.randint(200, 15000)} "-" "{user_agent}"'
        logs.append(log_line)

    return logs

# Generate and write logs
if __name__ == "__main__":
    logs = generate_t1595_log()
    with open('t1595.log', 'w') as f:
        for log in logs:
            f.write(log + '\n')
