import re
from urllib.parse import unquote
from collections import defaultdict

# Log format regex (common Apache/Nginx combined format)
LOG_PATTERN = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+)\s+-\s+-\s+\[(?P<timestamp>.*?)\]\s+"(?P<method>\w+)\s+(?P<endpoint>\S+)\s+HTTP/\d\.\d"\s+(?P<status>\d+)\s+(?P<size>\d+)\s+".*?"\s+"(?P<user_agent>.*?)"'
)

# Malicious signatures
SQLI_PATTERN = re.compile(r"(\%27|')\s*(OR|UNION|DROP|SELECT|INSERT)\b|--\s*$", re.IGNORECASE)
XSS_PATTERN = re.compile(r"(%3C|<)script(%3E|>)|onerror=|javascript:", re.IGNORECASE)

def analyze_logs(filename="access.log"):
    stats = {
        "total_logs": 0,
        "total_threats": 0,
        "threat_types": defaultdict(int)
    }
    alerts = []
    
    ip_attempts = defaultdict(list)
    
    try:
        with open(filename, 'r') as f:
            for line in f:
                stats["total_logs"] += 1
                match = LOG_PATTERN.match(line)
                if not match:
                    continue
                    
                data = match.groupdict()
                endpoint_decoded = unquote(data['endpoint'])
                
                is_threat = False
                threat_type = None
                severity = None
                
                # Check SQLi
                if SQLI_PATTERN.search(endpoint_decoded):
                    is_threat = True
                    threat_type = "SQLi"
                    severity = "High"
                
                # Check XSS
                elif XSS_PATTERN.search(endpoint_decoded):
                    is_threat = True
                    threat_type = "XSS"
                    severity = "Medium"
                
                # Check Brute Force (naive check based on POST /login over time for this exercise)
                if data['method'] == 'POST' and data['endpoint'] == '/login' and data['status'] == '401':
                    ip_attempts[data['ip']].append(data['timestamp'])
                    if len(ip_attempts[data['ip']]) > 5: # More than 5 failed attempts
                        is_threat = True
                        threat_type = "Brute Force"
                        severity = "High"
                
                if is_threat:
                    stats["total_threats"] += 1
                    stats["threat_types"][threat_type] += 1
                    alerts.append({
                        "timestamp": data['timestamp'],
                        "ip": data['ip'],
                        "method": data['method'],
                        "endpoint": data['endpoint'],
                        "type": threat_type,
                        "severity": severity
                    })
                    
    except FileNotFoundError:
        pass
        
    return stats, alerts
