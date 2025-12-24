import re
import socket
import concurrent.futures

def identify_service_by_banner(banner):
    if not banner:
        return "unknown"
    
    banner_lower = banner.lower()
    
    service_patterns = {
        "ssh": ["ssh", "openssh", "dropbear", "libssh", "twisted"],
        "ftp": ["ftp", "vsftpd", "proftpd", "pure-ftpd", "filezilla", "220-", "230 login"],
        "smtp": ["smtp", "esmtp", "postfix", "exim", "sendmail", "microsoft esmtp"],
        "http": ["http/", "apache", "nginx", "iis", "server:", "microsoft-httpapi", "lighttpd", "caddy"],
        "https": ["http/", "ssl", "tls", "cloudflare"],
        "telnet": ["telnet", "login:", "password:"],
        "mysql": ["mysql", "mariadb", "5.7.", "8.0.", "native password"],
        "postgresql": ["postgresql"],
        "redis": ["redis", "-err wrong number"],
        "mongodb": ["mongodb"],
        "elasticsearch": ["elasticsearch"],
        "vnc": ["vnc", "tigervnc", "tightvnc", "rfb "],
        "rdp": ["microsoft terminal services", "rdp", "credssp"],
        "samba": ["samba", "netbios", "samba smbd"],
        "docker": ["docker"],
        "kubernetes": ["kubernetes"],
        "nginx": ["nginx/"],
        "apache": ["apache/", "httpd"],
        "iis": ["microsoft-iis", "internet information services"],
        "tomcat": ["apache-tomcat", "tomcat"],
        "jenkins": ["jenkins", "x-jenkins"],
        "gitlab": ["gitlab", "_gitlab_session"],
        "wordpress": ["wordpress", "wp-", "xmlrpc.php"],
        "php": ["php/", "x-powered-by: php"],
        "nodejs": ["x-powered-by: express", "node.js"],
        "python": ["python/", "django", "flask"],
        "prometheus": ["prometheus"],
        "grafana": ["grafana"],
        "zabbix": ["zabbix"],
        "squid": ["squid", "proxy-agent: squid"],
        "haproxy": ["haproxy"],
        "irc": ["irc", "welcome to the irc"],
        "ldap": ["ldap", "389"],
        "snmp": ["snmp", "public", "private"],
        "oracle": ["oracle", "tns"],
        "sql server": ["sql server", "microsoft sql server"],
        "rabbitmq": ["rabbitmq", "amqp"],
        "memcached": ["memcached"],
        "cassandra": ["cassandra"],
        "couchdb": ["couchdb"],
    }
    
    for service, patterns in service_patterns.items():
        for pattern in patterns:
            if pattern in banner_lower:
                return service
    
    return "unknown"

def get_banner_from_port(host, port, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        if port in [80, 443, 8080, 8443, 8888]:
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        elif port == 21:
            sock.send(b"\r\n")
        elif port in [22, 2222]:
            sock.send(b"SSH-2.0-Test\r\n")
        elif port == 25:
            sock.send(b"EHLO test\r\n")
        elif port == 3306:
            sock.send(b"\x00\x00\x00\x0a\x00\x00\x00\x00\x00\x00\x00\x00")
        else:
            sock.send(b"\r\n\x00\r\n")
        
        banner = sock.recv(512).decode('utf-8', errors='ignore').strip()
        sock.close()
        
        return banner if banner and len(banner) > 2 else None
    except:
        return None

def scan_port_for_banner(host, port):
    try:
        ip = socket.gethostbyname(host)
    except:
        return None
    
    banner = get_banner_from_port(ip, port)
    
    if banner:
        service = identify_service_by_banner(banner)
        return {
            "host": host,
            "ip": ip,
            "port": port,
            "service": service,
            "banner": banner[:150]
        }
    
    return None

def run_fast_banner_scan():
    host = input("введите IP или домен -> ").strip()
    
    print("\nформат портов:")
    print("1. один порт: 80")
    print("2. диапазон: 20-25")
    print("3. список: 80,443,8080")
    print("4. быстро сканировать 50 популярных портов")
    
    choice = input("выберите вариант (1-4) -> ").strip()
    
    if choice == "4":
        ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 
                1723, 3306, 3389, 5900, 8080, 8443, 8888, 9000, 9001, 27017, 27018,
                5432, 6379, 9200, 11211, 2049, 2375, 2376, 3000, 5000, 5432, 5672,
                5984, 6379, 7474, 7687, 8000, 8008, 8081, 8090, 8181, 8200, 8300,
                8500, 9200, 9300, 11211, 27017, 28017, 50000]
        print(f"сканирую {len(ports)} популярных портов...")
    else:
        ports_input = input("введите порт(ы) -> ").strip()
        if "-" in ports_input:
            start, end = map(int, ports_input.split("-"))
            ports = list(range(start, end + 1))
        elif "," in ports_input:
            ports = [int(p.strip()) for p in ports_input.split(",")]
        else:
            ports = [int(ports_input)]
    
    print(f"сканирую {len(ports)} порт(ов) на {host}...")
    print("ожидайте...\n")
    
    results = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        future_to_port = {executor.submit(scan_port_for_banner, host, port): port for port in ports}
        
        for future in concurrent.futures.as_completed(future_to_port):
            result = future.result()
            if result:
                results.append(result)
                port = result["port"]
                service = result["service"]
                banner_preview = result["banner"][:40].replace("\n", " ").replace("\r", "")
                print(f"  [+] порт {port}: {service} - {banner_preview}...")
    
    if results:
        print(f"\nнайдено {len(results)} портов с баннерами:")
        print("-" * 70)
        
        for result in sorted(results, key=lambda x: x["port"]):
            print(f"порт {result['port']} ({result['service']}):")
            print(f"  {result['banner'][:120]}")
            print()
    else:
        print("порты с баннерами не найдены")
    
    return results