import requests
import re
import json
import time
import socket
from urllib.parse import urljoin, urlparse
from datetime import datetime
from bs4 import BeautifulSoup
import dns.resolver
import concurrent.futures

class AdvancedOSINTCollector:
    def __init__(self, domain):
        self.domain = domain
        self.results = {}
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        })
    
    def find_breach_data(self):
        try:
            breaches = []
            url = f"https://haveibeenpwned.com/api/v3/breaches"
            headers = {"User-Agent": "Mozilla/5.0"}
            
            response = self.session.get(url, headers=headers, timeout=15)
            if response.status_code == 200:
                data = response.json()
                for breach in data:
                    if breach.get("Domain", "").lower() == self.domain.lower():
                        breach_info = {
                            "name": breach.get("Name"),
                            "date": breach.get("BreachDate"),
                            "compromised_data": breach.get("DataClasses", []),
                            "description": breach.get("Description", "")[:150]
                        }
                        breaches.append(breach_info)
            
            time.sleep(1)
            
            crt_url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            crt_response = self.session.get(crt_url, timeout=10)
            if crt_response.status_code == 200:
                try:
                    crt_data = crt_response.json()
                    for cert in crt_data:
                        if "not_after" in cert:
                            expiry_date = cert["not_after"]
                            if "2030" in expiry_date or "2031" in expiry_date:
                                breaches.append({
                                    "name": "SSL_Certificate_Expiry",
                                    "date": expiry_date[:10],
                                    "compromised_data": ["SSL_Cert_Info"],
                                    "description": f"Длинный срок действия сертификата: {expiry_date}"
                                })
                                break
                except:
                    pass
            
            return breaches
        except:
            return []
    
    def search_github_exposed_data(self):
        exposed_items = []
        
        search_terms = [
            f'"{self.domain}" filename:.env',
            f'"{self.domain}" filename:config',
            f'"{self.domain}" "api_key"',
            f'"{self.domain}" "secret"',
            f'"{self.domain}" "password"',
            f'"{self.domain}" "private_key"',
            f'"{self.domain}" extension:json',
            f'"{self.domain}" extension:yaml',
            f'"{self.domain}" extension:yml',
            f'"{self.domain}" "docker-compose"',
            f'"{self.domain}" "dockerfile"'
        ]
        
        for term in search_terms[:5]:
            try:
                search_url = "https://api.github.com/search/code"
                params = {"q": term, "per_page": 3}
                headers = {"Accept": "application/vnd.github.v3+json", "User-Agent": "Mozilla/5.0"}
                
                response = self.session.get(search_url, headers=headers, params=params, timeout=15)
                if response.status_code == 200:
                    data = response.json()
                    if data.get("total_count", 0) > 0:
                        for item in data.get("items", [])[:2]:
                            item_info = {
                                "repository": item.get("repository", {}).get("full_name", "unknown"),
                                "file_path": item.get("path", "unknown"),
                                "url": item.get("html_url", ""),
                                "search_term": term,
                                "score": item.get("score", 0)
                            }
                            exposed_items.append(item_info)
                
                time.sleep(3)
            except:
                continue
        
        return exposed_items
    
    def scan_for_exposed_configs(self):
        configs_found = []
        
        common_config_paths = [
            "/.env",
            "/config.json",
            "/config.yml",
            "/config.yaml",
            "/application.properties",
            "/settings.py",
            "/config/database.yml",
            "/.git/config",
            "/docker-compose.yml",
            "/.aws/credentials"
        ]
        
        protocols = ["http://", "https://"]
        
        for protocol in protocols:
            base_url = f"{protocol}{self.domain}"
            
            for path in common_config_paths[:5]:
                try:
                    test_url = base_url + path
                    response = self.session.get(test_url, timeout=5, verify=False)
                    
                    if response.status_code == 200:
                        content = response.text[:500]
                        
                        sensitive_patterns = [
                            r'password\s*[:=]\s*["\']?([^"\'\s]+)',
                            r'secret\s*[:=]\s*["\']?([^"\'\s]+)',
                            r'api[_-]?key\s*[:=]\s*["\']?([^"\'\s]+)',
                            r'token\s*[:=]\s*["\']?([^"\'\s]+)',
                            r'aws[_-]?access[_-]?key\s*[:=]\s*["\']?([^"\'\s]+)',
                            r'aws[_-]?secret[_-]?key\s*[:=]\s*["\']?([^"\'\s]+)'
                        ]
                        
                        found_secrets = []
                        for pattern in sensitive_patterns:
                            matches = re.findall(pattern, content, re.IGNORECASE)
                            found_secrets.extend(matches)
                        
                        if found_secrets:
                            configs_found.append({
                                "url": test_url,
                                "status_code": response.status_code,
                                "secrets_found": len(found_secrets),
                                "sample_secrets": found_secrets[:3]
                            })
                    
                    time.sleep(0.5)
                except:
                    continue
        
        return configs_found
    
    def find_documents_with_metadata(self):
        documents = []
        
        search_patterns = [
            f'site:{self.domain} filetype:pdf',
            f'site:{self.domain} filetype:docx',
            f'site:{self.domain} filetype:xlsx',
            f'site:{self.domain} filetype:pptx',
            f'site:{self.domain} ext:pdf',
            f'site:{self.domain} ext:docx'
        ]
        
        doc_urls = []
        
        base_url = f"https://{self.domain}"
        try:
            response = self.session.get(base_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for link in soup.find_all('a', href=True):
                href = link['href']
                if any(href.lower().endswith(ext) for ext in ['.pdf', '.docx', '.xlsx', '.pptx', '.doc']):
                    full_url = urljoin(base_url, href)
                    doc_urls.append(full_url)
        except:
            pass
        
        for url in doc_urls[:10]:
            try:
                head_response = self.session.head(url, timeout=5)
                if head_response.status_code == 200:
                    content_type = head_response.headers.get('content-type', '')
                    if any(doc_type in content_type.lower() for doc_type in ['pdf', 'word', 'excel', 'powerpoint']):
                        documents.append({
                            "url": url,
                            "type": content_type,
                            "size": head_response.headers.get('content-length', 'unknown')
                        })
            except:
                continue
        
        return documents
    
    def find_employees_linkedin(self):
        employees = []
        
        linkedin_patterns = [
            f'site:linkedin.com/in/ "@{self.domain}"',
            f'site:linkedin.com/in/ "{self.domain}"',
            f'site:linkedin.com/company/ "{self.domain}"',
            f'"{self.domain}" "linkedin.com/in/"',
            f'"{self.domain}" "works at" site:linkedin.com'
        ]
        
        for pattern in linkedin_patterns:
            employees.append({
                "search_query": pattern,
                "source": "linkedin",
                "type": "employee_search"
            })
        
        try:
            company_url = f"https://www.linkedin.com/company/{self.domain}"
            response = self.session.get(company_url, timeout=10, allow_redirects=True)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                meta_tags = soup.find_all('meta')
                for tag in meta_tags:
                    if 'property' in tag.attrs and 'content' in tag.attrs:
                        if 'employee' in tag.attrs['property'].lower():
                            employees.append({
                                "metadata_found": tag.attrs['property'],
                                "content": tag.attrs['content'][:100],
                                "source": "linkedin_meta"
                            })
        except:
            pass
        
        return employees
    
    def discover_subdomains(self):
        subdomains = set()
        
        sources = [
            f"https://crt.sh/?q=%.{self.domain}&output=json",
            f"https://api.hackertarget.com/hostsearch/?q={self.domain}",
            f"https://www.virustotal.com/ui/domains/{self.domain}/subdomains?limit=40"
        ]
        
        for source in sources[:2]:
            try:
                response = self.session.get(source, timeout=15)
                if response.status_code == 200:
                    if "crt.sh" in source:
                        try:
                            data = response.json()
                            for item in data:
                                if "name_value" in item:
                                    names = item["name_value"].split('\n')
                                    for name in names:
                                        if self.domain in name and '*' not in name:
                                            subdomains.add(name.strip().lower())
                        except:
                            pass
                    elif "hackertarget" in source:
                        lines = response.text.strip().split('\n')
                        for line in lines:
                            if ',' in line:
                                subdomain = line.split(',')[0].strip()
                                if self.domain in subdomain:
                                    subdomains.add(subdomain.lower())
                
                time.sleep(2)
            except:
                continue
        
        try:
            resolver = dns.resolver.Resolver()
            common_subs = ['www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging', 'blog', 'shop']
            
            for sub in common_subs:
                try:
                    target = f"{sub}.{self.domain}"
                    resolver.resolve(target, 'A')
                    subdomains.add(target)
                except:
                    pass
        except:
            pass
        
        return list(subdomains)[:50]
    
    def check_exposed_services(self):
        services = []
        
        common_ports = {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            80: "http",
            110: "pop3",
            143: "imap",
            443: "https",
            445: "smb",
            1433: "mssql",
            1521: "oracle",
            3306: "mysql",
            3389: "rdp",
            5432: "postgresql",
            5900: "vnc",
            6379: "redis",
            8080: "http-proxy",
            8443: "https-alt",
            27017: "mongodb",
            9200: "elasticsearch"
        }
        
        try:
            ip = socket.gethostbyname(self.domain)
        except:
            return services
        
        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    service_name = common_ports.get(port, f"port_{port}")
                    
                    try:
                        sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock2.settimeout(2)
                        sock2.connect((ip, port))
                        sock2.send(b"\r\n")
                        banner = sock2.recv(256).decode('utf-8', errors='ignore').strip()
                        sock2.close()
                    except:
                        banner = None
                    
                    return {
                        "port": port,
                        "service": service_name,
                        "ip": ip,
                        "banner": banner[:100] if banner else None
                    }
            except:
                pass
            return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(check_port, port) for port in common_ports.keys()]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    services.append(result)
        
        return services
    
    def run_complete_scan(self):
        print(f"\nзапущен технический OSINT сбор для: {self.domain}")
        print("=" * 70)
        
        tasks = [
            ("поиск утечек данных", self.find_breach_data),
            ("поиск на github", self.search_github_exposed_data),
            ("сканирование конфигов", self.scan_for_exposed_configs),
            ("поиск документов", self.find_documents_with_metadata),
            ("поиск сотрудников", self.find_employees_linkedin),
            ("поиск поддоменов", self.discover_subdomains),
            ("проверка сервисов", self.check_exposed_services)
        ]
        
        all_results = {}
        
        for task_name, task_func in tasks:
            print(f"[*] {task_name}...")
            try:
                result = task_func()
                all_results[task_name] = result
                
                if isinstance(result, list):
                    print(f"    найдено: {len(result)} записей")
                else:
                    print(f"    завершено")
                
                time.sleep(2)
            except Exception as e:
                print(f"    ошибка: {str(e)[:50]}")
                all_results[task_name] = []
        
        self.results = all_results
        return all_results
    
    def generate_report(self):
        report = {
            "domain": self.domain,
            "scan_date": datetime.now().isoformat(),
            "summary": {}
        }
        
        total_findings = 0
        findings_details = {}
        
        for category, data in self.results.items():
            if isinstance(data, list):
                count = len(data)
                total_findings += count
                report["summary"][category] = count
                findings_details[category] = data
        
        report["total_findings"] = total_findings
        report["detailed_findings"] = findings_details
        
        return report
    
    def print_summary(self):
        print(f"\n{'='*70}")
        print(f"сводка: {self.domain}")
        print(f"{'='*70}")
        
        for category, data in self.results.items():
            if isinstance(data, list):
                count = len(data)
                if count > 0:
                    print(f"\n[+] {category.upper()}: {count} находок")
                    
                    if category == "поиск утечек данных" and data:
                        for i, leak in enumerate(data[:3], 1):
                            print(f"    {i}. {leak.get('name', 'unknown')} ({leak.get('date', 'unknown')})")
                    
                    elif category == "поиск на github" and data:
                        for i, item in enumerate(data[:3], 1):
                            repo = item.get('repository', 'unknown')
                            print(f"    {i}. {repo[:40]}...")
                    
                    elif category == "поиск поддоменов" and data:
                        print("    найденные поддомены:")
                        for i, sub in enumerate(data[:10], 1):
                            print(f"      {i}. {sub}")
                        if len(data) > 10:
                            print(f"      ... и еще {len(data) - 10} поддоменов")
                    
                    elif category == "проверка сервисов" and data:
                        print("    открытые порты:")
                        for service in data[:5]:
                            port = service.get('port', '')
                            svc = service.get('service', '')
                            print(f"      {port}/tcp - {svc}")

def format_osint_report(report):
    domain = report.get('domain', 'unknown')
    scan_date = report.get('scan_date', 'unknown')
    
    print(f"\n{'='*70}")
    print(f"📊 отчет")
    print(f"{'='*70}")
    print(f"🎯 домен: {domain}")
    print(f"📅 дата сканирования: {scan_date[:19]}")
    print(f"{'='*70}")
    
    summary = report.get('summary', {})
    total = report.get('total_findings', 0)
    
    print(f"\n📈 сводка находок: {total} всего")
    print("-" * 50)
    
    categories = {
        'поиск утечек данных': '🔓 утечки данных',
        'поиск на github': '💾 gitHub секреты',
        'сканирование конфигов': '⚙️ конфигурации',
        'поиск документов': '📄 документы',
        'поиск сотрудников': '👥 сотрудники',
        'поиск поддоменов': '🌐 поддомены',
        'проверка сервисов': '🖥️ сервисы'
    }
    
    for key, display_name in categories.items():
        count = summary.get(key, 0)
        icon = "✅" if count > 0 else "❌"
        print(f"{icon} {display_name}: {count}")
    
    print(f"\n{'='*70}")
    print(f"🔍 детальная инфа")
    print(f"{'='*70}")
    
    details = report.get('detailed_findings', {})
    
    if details.get('поиск поддоменов'):
        print(f"\n🌐 найденные поддомены ({len(details['поиск поддоменов'])}):")
        print("-" * 40)
        for i, subdomain in enumerate(details['поиск поддоменов'], 1):
            print(f"  {i}. {subdomain}")
    
    if details.get('поиск сотрудников'):
        print(f"\n👥 поиск сотрудников:")
        print("-" * 40)
        print("поисковые запросы для LinkedIn:")
        for i, query in enumerate(details['поиск сотрудников'][:3], 1):
            print(f"  {i}. {query.get('search_query', '')}")
        
        if len(details['поиск сотрудников']) > 3:
            print(f"  ... и еще {len(details['поиск сотрудников']) - 3} запросов")
    
    print("рекомендации: ")
    recommendations = []
    
    if details.get('поиск поддоменов'):
        if len(details['поиск поддоменов']) > 1:
            recommendations.append(f"1. проверить поддомены на уязвимости: {', '.join(details['поиск поддоменов'][:3])}")
    
    if summary.get('поиск сотрудников') > 0:
        recommendations.append("2. использовать поисковые запросы для поиска сотрудников в LinkedIn")
    
    if total == 0:
        recommendations.append("3. домен хорошо защищен или малоизвестен. Проверить через другие инструменты OSINT")
    
    for i, rec in enumerate(recommendations, 1):
        print(f"{i}. {rec}")
    
    print(f"\nстатус: ", end="")
    if total < 5:
        print("🟢 низкий риск (мало находок)")
    elif total < 10:
        print("🟡 средний риск (несколько находок)")
    else:
        print("🔴 высокий риск (много находок)")
    
    print(f"{'='*70}")
    
    return True

def run_advanced_osint():
    domain = input("введите домен для сбора информации -> ").strip().lower()
    
    if not domain or ' ' in domain:
        print("ошибка: неверный формат домена")
        return None
    
    print(f"\nинициализация сбора для {domain}...")
    print("это займет 2-3 минуты...")
    
    collector = AdvancedOSINTCollector(domain)
    results = collector.run_complete_scan()
    
    collector.print_summary()
    
    report = collector.generate_report()
    
    return report