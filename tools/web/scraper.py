import asyncio
import aiohttp
from urllib.parse import urlparse, urljoin, urldefrag
from bs4 import BeautifulSoup
import re
import json
from datetime import datetime
from collections import deque
import hashlib
import time
import ssl

class advanced_spider:
    def __init__(self, start_url, max_pages=100, max_depth=3):
        self.start_url = start_url
        self.max_pages = max_pages
        self.max_depth = max_depth
        
        parsed = urlparse(start_url)
        self.base_domain = parsed.netloc
        self.base_scheme = parsed.scheme
        
        self.visited = set()
        self.to_crawl = deque()
        self.results = {
            "страницы": [],
            "формы": [],
            "ссылки": [],
            "файлы": [],
            "api": [],
            "ключи": [],
            "эмейлы": [],
            "комментарии": [],
            "метаданные": []
        }
        
        self.session = None
        self.connector = None
    
    async def init_session(self):
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        
        timeout = aiohttp.ClientTimeout(total=30, connect=10)
        self.connector = aiohttp.TCPConnector(
            ssl=ssl_context,
            limit=20,
            ttl_dns_cache=300
        )
        
        self.session = aiohttp.ClientSession(
            connector=self.connector,
            timeout=timeout,
            headers={
                "user-agent": "mozilla/5.0 (windows nt 10.0; win64; x64) applewebkit/537.36 (khtml, like gecko) chrome/120.0.0.0 safari/537.36",
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "accept-language": "ru-ru,ru;q=0.9,en-us;q=0.8,en;q=0.7",
                "accept-encoding": "gzip, deflate, br",
                "connection": "keep-alive",
                "upgrade-insecure-requests": "1"
            }
        )
    
    async def close_session(self):
        if self.session:
            await self.session.close()
        if self.connector:
            await self.connector.close()
    
    def normalize_url(self, url, base_url):
        if not url:
            return None
        
        url = url.strip()
        
        if url.startswith('//'):
            url = self.base_scheme + ':' + url
        elif url.startswith('/'):
            url = self.base_scheme + '://' + self.base_domain + url
        elif not url.startswith(('http://', 'https://')):
            url = urljoin(base_url, url)
        
        url, _ = urldefrag(url)
        
        parsed = urlparse(url)
        if not parsed.netloc:
            return None
        
        return url
    
    def should_crawl(self, url):
        parsed = urlparse(url)
        
        if not parsed.netloc.endswith(self.base_domain):
            return False
        
        if parsed.path.endswith(('.jpg', '.jpeg', '.png', '.gif', '.pdf', '.zip', '.rar', '.tar', '.gz')):
            return False
        
        if '#' in url:
            return False
        
        if 'logout' in url.lower() or 'exit' in url.lower():
            return False
        
        return True
    
    async def fetch_page(self, url, depth):
        try:
            async with self.session.get(url, allow_redirects=True, ssl=False) as response:
                if response.status != 200:
                    return None
                
                content = await response.text()
                final_url = str(response.url)
                
                return {
                    "url": final_url,
                    "content": content,
                    "status": response.status,
                    "headers": dict(response.headers),
                    "depth": depth
                }
        except:
            return None
    
    def extract_links(self, html, base_url):
        soup = BeautifulSoup(html, 'html.parser')
        links = []
        
        for tag in soup.find_all(['a', 'link', 'script', 'img'], href=True):
            href = tag.get('href', '')
            if href:
                normalized = self.normalize_url(href, base_url)
                if normalized and normalized not in self.visited:
                    links.append(normalized)
        
        for tag in soup.find_all(['script', 'img'], src=True):
            src = tag.get('src', '')
            if src:
                normalized = self.normalize_url(src, base_url)
                if normalized:
                    links.append(normalized)
        
        for tag in soup.find_all('form', action=True):
            action = tag.get('action', '')
            if action:
                normalized = self.normalize_url(action, base_url)
                if normalized:
                    links.append(normalized)
        
        return list(set(links))
    
    def analyze_page(self, url, html, depth):
        soup = BeautifulSoup(html, 'html.parser')
        page_id = hashlib.md5(url.encode()).hexdigest()[:8]
        
        page_info = {
            "id": page_id,
            "url": url,
            "depth": depth,
            "title": "",
            "links_count": 0,
            "forms_count": 0,
            "secrets_found": 0,
            "timestamp": datetime.now().isoformat()
        }
        
        title_tag = soup.find('title')
        if title_tag:
            page_info["title"] = title_tag.text.strip()[:100]
        
        page_info["links_count"] = len(soup.find_all('a', href=True))
        
        forms = soup.find_all('form')
        page_info["forms_count"] = len(forms)
        
        for form in forms:
            form_info = self.analyze_form(form, url)
            if form_info:
                self.results["формы"].append(form_info)
        
        self.extract_secrets(html, url)
        self.extract_emails(html, url)
        self.extract_comments(html, url)
        self.extract_api_endpoints(html, url)
        self.extract_files(html, url)
        self.extract_metadata(soup, url)
        
        self.results["страницы"].append(page_info)
        
        return page_info
    
    def analyze_form(self, form, page_url):
        try:
            form_info = {
                "page": page_url,
                "action": form.get('action', ''),
                "method": form.get('method', 'get').lower(),
                "inputs": []
            }
            
            inputs = form.find_all(['input', 'textarea', 'select'])
            for inp in inputs:
                input_type = inp.get('type', 'text')
                input_name = inp.get('name', '')
                input_value = inp.get('value', '')
                
                if input_name:
                    form_info["inputs"].append({
                        "name": input_name,
                        "type": input_type,
                        "value": input_value[:50],
                        "sensitive": self.is_sensitive_field(input_name)
                    })
            
            return form_info if form_info["inputs"] else None
        except:
            return None
    
    def is_sensitive_field(self, field_name):
        sensitive_patterns = [
            r'pass', r'pwd', r'secret', r'token', r'key', 
            r'auth', r'credit', r'card', r'cvv', r'cvc',
            r'ssn', r'security', r'private', r'hidden'
        ]
        
        field_lower = field_name.lower()
        for pattern in sensitive_patterns:
            if re.search(pattern, field_lower):
                return True
        return False
    
    def extract_secrets(self, html, page_url):
        secret_patterns = {
            "ключи_api": [
                r'api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']',
                r'secret["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']',
                r'token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']'
            ],
            "aws_ключи": [
                r'aws[_-]?access[_-]?key["\']?\s*[:=]\s*["\']([A-Z0-9]{20})["\']',
                r'aws[_-]?secret[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9/+]{40})["\']'
            ],
            "пароли": [
                r'password["\']?\s*[:=]\s*["\']([^"\']{6,})["\']',
                r'pass["\']?\s*[:=]\s*["\']([^"\']{6,})["\']'
            ],
            "jwt": [
                r'eyJ[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]{5,}'
            ]
        }
        
        for secret_type, patterns in secret_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, html, re.IGNORECASE)
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0]
                    
                    self.results["ключи"].append({
                        "type": secret_type,
                        "value": match[:50] + "..." if len(match) > 50 else match,
                        "page": page_url,
                        "pattern": pattern[:30]
                    })
    
    def extract_emails(self, html, page_url):
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        emails = re.findall(email_pattern, html)
        
        for email in list(set(emails))[:10]:
            self.results["эмейлы"].append({
                "email": email,
                "page": page_url
            })
    
    def extract_comments(self, html, page_url):
        comment_patterns = [
            r'<!--(.*?)-->',
            r'\/\*(.*?)\*\/',
            r'\/\/(.*?)\n'
        ]
        
        all_comments = []
        for pattern in comment_patterns:
            comments = re.findall(pattern, html, re.DOTALL)
            all_comments.extend(comments)
        
        for comment in all_comments[:5]:
            comment_text = comment.strip()
            if comment_text and len(comment_text) > 5:
                self.results["комментарии"].append({
                    "comment": comment_text[:100] + "..." if len(comment_text) > 100 else comment_text,
                    "page": page_url
                })
    
    def extract_api_endpoints(self, html, page_url):
        api_patterns = [
            r'["\'](/api/v[0-9]/[^"\']+)["\']',
            r'["\'](/rest/[^"\']+)["\']',
            r'["\'](/graphql[^"\']*)["\']',
            r'["\'](/soap/[^"\']+)["\']',
            r'["\'](/ajax/[^"\']+)["\']',
            r'["\'](/json/[^"\']+)["\']'
        ]
        
        for pattern in api_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                
                full_url = urljoin(page_url, match)
                self.results["api"].append({
                    "endpoint": match,
                    "full_url": full_url,
                    "page": page_url
                })
    
    def extract_files(self, html, page_url):
        file_patterns = [
            r'["\']([^"\']+\.pdf)["\']',
            r'["\']([^"\']+\.docx?)["\']',
            r'["\']([^"\']+\.xlsx?)["\']',
            r'["\']([^"\']+\.csv)["\']',
            r'["\']([^"\']+\.json)["\']',
            r'["\']([^"\']+\.xml)["\']',
            r'["\']([^"\']+\.sql)["\']',
            r'["\']([^"\']+\.env)["\']',
            r'["\']([^"\']+\.config)["\']'
        ]
        
        for pattern in file_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                
                full_url = urljoin(page_url, match)
                self.results["файлы"].append({
                    "filename": match,
                    "url": full_url,
                    "page": page_url
                })
    
    def extract_metadata(self, soup, page_url):
        meta_tags = soup.find_all('meta')
        
        for meta in meta_tags[:20]:
            name = meta.get('name', '') or meta.get('property', '')
            content = meta.get('content', '')
            
            if name and content:
                self.results["метаданные"].append({
                    "name": name,
                    "content": content[:100],
                    "page": page_url
                })
    
    async def crawl(self):
        await self.init_session()
        
        self.to_crawl.append((self.start_url, 0))
        
        crawled_count = 0
        
        while self.to_crawl and crawled_count < self.max_pages:
            url, depth = self.to_crawl.popleft()
            
            if url in self.visited or depth > self.max_depth:
                continue
            
            self.visited.add(url)
            crawled_count += 1
            
            print(f"сканирую [{crawled_count}/{self.max_pages}] {url[:60]}...")
            
            page_data = await self.fetch_page(url, depth)
            
            if not page_data:
                continue
            
            self.analyze_page(url, page_data["content"], depth)
            
            if depth < self.max_depth:
                links = self.extract_links(page_data["content"], url)
                for link in links:
                    if self.should_crawl(link) and link not in self.visited:
                        self.to_crawl.append((link, depth + 1))
            
            await asyncio.sleep(0.1)
        
        await self.close_session()
        
        return self.results
    
    def print_results(self):
        print(f"\n{'='*80}")
        print(f"📊 отчет сканирования: {self.start_url}")
        print(f"{'='*80}")
        
        print(f"\n📈 статистика сканирования:")
        print(f"   всего страниц: {len(self.results['страницы'])}")
        print(f"   уникальных ссылок: {len(set([p['url'] for p in self.results['страницы']]))}")
        print(f"   глубина сканирования: {self.max_depth}")
        
        print(f"\n{'='*80}")
        print(f"🔍 найденные уязвимости и данные:")
        
        if self.results["ключи"]:
            print(f"\n   🔐 секретные ключи ({len(self.results['ключи'])}):")
            for i, key in enumerate(self.results["ключи"][:5], 1):
                print(f"      {i}. {key['type']}: {key['value']}")
                print(f"          страница: {key['page'][:50]}...")
        
        if self.results["формы"]:
            print(f"\n   📝 формы ({len(self.results['формы'])}):")
            for i, form in enumerate(self.results["формы"][:3], 1):
                print(f"      {i}. {form['method'].upper()} {form['action'][:50]}")
                sensitive_inputs = [inp for inp in form['inputs'] if inp['sensitive']]
                if sensitive_inputs:
                    print(f"          чувствительные поля: {', '.join([inp['name'] for inp in sensitive_inputs])}")
        
        if self.results["эмейлы"]:
            print(f"\n   📧 email-адреса ({len(self.results['эмейлы'])}):")
            emails = list(set([e['email'] for e in self.results['эмейлы']]))
            for i, email in enumerate(emails[:5], 1):
                print(f"      {i}. {email}")
        
        if self.results["api"]:
            print(f"\n   🔌 api endpoints ({len(self.results['api'])}):")
            endpoints = list(set([e['endpoint'] for e in self.results['api']]))
            for i, endpoint in enumerate(endpoints[:5], 1):
                print(f"      {i}. {endpoint}")
        
        if self.results["файлы"]:
            print(f"\n   📁 файлы ({len(self.results['файлы'])}):")
            files = list(set([f['filename'] for f in self.results['файлы']]))
            for i, file in enumerate(files[:5], 1):
                print(f"      {i}. {file}")
        
        print(f"\n{'='*80}")
        print(f"💡 рекомендации для пентеста:")
        
        recommendations = []
        
        if self.results["ключи"]:
            recommendations.append("проверить найденные ключи на валидность")
        
        if self.results["формы"]:
            recommendations.append("протестировать формы на sql-инъекции и xss")
        
        if self.results["api"]:
            recommendations.append("проанализировать api endpoints на уязвимости")
        
        if self.results["эмейлы"]:
            recommendations.append("использовать email для фишингового тестирования")
        
        if recommendations:
            for i, rec in enumerate(recommendations, 1):
                print(f"   {i}. {rec}")
        else:
            print("   🤔 рекомендаций нет - слишком мало данных")
        
        print(f"\n{'='*80}")
        
        if len(self.results["страницы"]) > 0:
            print(f"\n📄 примеры найденных страниц:")
            for page in self.results["страницы"][:3]:
                print(f"   🌐 {page['url'][:60]}...")
                print(f"      заголовок: {page['title']}")
                print(f"      ссылок: {page['links_count']}, форм: {page['forms_count']}")
        
        print(f"\n{'='*80}")
        print(f"⏱ время завершения: {datetime.now().strftime('%H:%M:%S')}")
        print(f"{'='*80}")

async def run_spider():
    url = input("\nвведите url для сканирования -> ").strip()
    
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    max_pages = input("максимум страниц (по умолчанию 50) -> ").strip()
    max_pages = int(max_pages) if max_pages.isdigit() else 50
    
    max_depth = input("максимальная глубина (по умолчанию 3) -> ").strip()
    max_depth = int(max_depth) if max_depth.isdigit() else 3
    
    print(f"\nначинаю сканирование {url}")
    print(f"макс страниц: {max_pages}, макс глубина: {max_depth}")
    print("подождите, это может занять время...")
    
    spider = advanced_spider(url, max_pages, max_depth)
    results = await spider.crawl()
    
    spider.print_results()
    
    save = input("\nсохранить полный отчет? (y/n) -> ").lower()
    if save == 'y':
        filename = f"spider_report_{urlparse(url).netloc}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"отчет сохранен в {filename}")
