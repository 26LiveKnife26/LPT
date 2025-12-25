import socket

def whois_lookup(domain, whois_server="whois.iana.org", port=43):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((whois_server, port))
        sock.send(f"{domain}\r\n".encode())
        
        response = b""
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data
        
        sock.close()
        result = response.decode('utf-8', errors='ignore')
        
        if whois_server == "whois.iana.org":
            for line in result.split('\n'):
                if "refer:" in line.lower():
                    referral = line.split(":")[1].strip()
                    if referral:
                        return whois_lookup(domain, referral)
        
        return result
    except Exception:
        return "Ошибка запроса"
    