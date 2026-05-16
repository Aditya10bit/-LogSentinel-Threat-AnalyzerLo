import random
import datetime
from urllib.parse import quote

def generate_logs(filename="access.log"):
    logs = []
    
    # Base configuration
    start_time = datetime.datetime.now() - datetime.timedelta(days=1)
    
    # 1. Normal Traffic (500 lines)
    normal_ips = [f"192.168.1.{random.randint(2, 254)}" for _ in range(50)]
    endpoints = ["/", "/about", "/contact", "/products", "/css/style.css", "/js/app.js", "/images/logo.png", "/login"]
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Mobile Safari/537.36"
    ]
    
    for _ in range(500):
        ip = random.choice(normal_ips)
        dt = start_time + datetime.timedelta(minutes=random.randint(1, 1440))
        timestamp = dt.strftime("%d/%b/%Y:%H:%M:%S +0000")
        method = random.choice(["GET", "POST"]) if random.random() > 0.8 else "GET"
        endpoint = random.choice(endpoints)
        status = random.choice([200, 200, 200, 200, 301, 404])
        ua = random.choice(user_agents)
        logs.append((dt, f'{ip} - - [{timestamp}] "{method} {endpoint} HTTP/1.1" {status} {random.randint(100, 5000)} "-" "{ua}"\n'))
        
    # 2. Malicious Traffic (50 lines total)
    malicious_ip_sqli = "203.0.113.42"
    malicious_ip_xss = "198.51.100.7"
    malicious_ip_brute = "104.244.42.1"
    
    malicious_logs = []
    
    # SQLi (15 lines)
    sqli_payloads = ["' OR 1=1 --", "admin' --", "' UNION SELECT null, null --", "1; DROP TABLE users"]
    for _ in range(15):
        dt = start_time + datetime.timedelta(minutes=random.randint(1, 1440))
        timestamp = dt.strftime("%d/%b/%Y:%H:%M:%S +0000")
        payload = random.choice(sqli_payloads)
        encoded_payload = quote(payload)
        endpoint = f"/login?user={encoded_payload}"
        logs.append((dt, f'{malicious_ip_sqli} - - [{timestamp}] "GET {endpoint} HTTP/1.1" 200 1200 "-" "curl/7.68.0"\n'))

    # XSS (15 lines)
    xss_payloads = ["<script>alert(1)</script>", "\"><script>alert('XSS')</script>", "<img src=x onerror=alert(1)>"]
    for _ in range(15):
        dt = start_time + datetime.timedelta(minutes=random.randint(1, 1440))
        timestamp = dt.strftime("%d/%b/%Y:%H:%M:%S +0000")
        payload = random.choice(xss_payloads)
        encoded_payload = quote(payload)
        endpoint = f"/search?q={encoded_payload}"
        logs.append((dt, f'{malicious_ip_xss} - - [{timestamp}] "GET {endpoint} HTTP/1.1" 200 3400 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"\n'))

    # Brute Force (20 lines in rapid succession)
    brute_force_start = start_time + datetime.timedelta(hours=5)
    for i in range(20):
        dt = brute_force_start + datetime.timedelta(seconds=i*2) # 2 seconds apart
        timestamp = dt.strftime("%d/%b/%Y:%H:%M:%S +0000")
        logs.append((dt, f'{malicious_ip_brute} - - [{timestamp}] "POST /login HTTP/1.1" 401 500 "-" "python-requests/2.25.1"\n'))
        
    # Sort logs by datetime
    logs.sort(key=lambda x: x[0])
    
    with open(filename, 'w') as f:
        for _, log_entry in logs:
            f.write(log_entry)
            
    print(f"Generated {len(logs)} log entries in {filename}")

if __name__ == "__main__":
    generate_logs()
