import requests
import re
import time
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from datetime import datetime

class wayback_scraper:
    def __init__(self, domain):
        self.domain = domain
        self.session = requests.Session()
        self.session.headers.update({
            "user-agent": "mozilla/5.0 (windows nt 10.0; win64; x64) applewebkit/537.36",
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
        })
    
    def get_cdx_data(self):
        snapshots = []
        try:
            url = "https://web.archive.org/cdx/search/cdx"
            params = {
                "url": self.domain + "/*",
                "output": "json",
                "fl": "timestamp,original,mimetype,statuscode",
                "collapse": "urlkey",
                "limit": 50
            }
            
            response = self.session.get(url, params=params, timeout=30)
            if response.status_code == 200:
                try:
                    data = response.json()
                    if len(data) > 1:
                        for row in data[1:]:
                            if len(row) >= 3:
                                timestamp = row[0]
                                original = row[1]
                                mimetype = row[2] if len(row) > 2 else ""
                                statuscode = row[3] if len(row) > 3 else ""
                                
                                if self.domain in original:
                                    snapshots.append({
                                        "ts": timestamp,
                                        "url": original,
                                        "type": mimetype,
                                        "code": statuscode,
                                        "wayback": f"https://web.archive.org/web/{timestamp}id_/{original}"
                                    })
                except:
                    pass
        except:
            pass
        
        return snapshots
    
    def find_interesting_urls(self, snapshots):
        interesting = {
            "админки": [],
            "конфиги": [],
            "бэкапы": [],
            "логи": [],
            "git": [],
            "api": [],
            "логины": [],
            "базы": [],
            "файлы": []
        }
        
        patterns = {
            "админки": [r"/admin", r"/wp-admin", r"/administrator", r"/backend", r"/cpanel", r"/panel"],
            "конфиги": [r"\.env", r"config\.", r"\.cfg", r"\.conf", r"\.ini", r"\.properties"],
            "бэкапы": [r"\.bak", r"\.old", r"backup", r"dump", r"\.sql", r"\.tar", r"\.gz"],
            "логи": [r"\.log", r"logs/", r"debug", r"error", r"access_log"],
            "git": [r"\.git/", r"\.gitignore", r"\.gitconfig"],
            "api": [r"/api/", r"/v1/", r"/v2/", r"/graphql", r"/rest/", r"/soap/"],
            "логины": [r"/login", r"/signin", r"/auth", r"/register", r"/signup", r"/account"],
            "базы": [r"/phpmyadmin", r"/adminer", r"/mysql", r"/dbadmin", r"/pma"],
            "файлы": [r"\.txt", r"\.pdf", r"\.doc", r"\.xls", r"\.csv", r"\.xml", r"\.json"]
        }
        
        for snap in snapshots:
            url_lower = snap["url"].lower()
            
            for cat, pats in patterns.items():
                for pat in pats:
                    if re.search(pat, url_lower):
                        found = False
                        for existing in interesting[cat]:
                            if existing["url"] == snap["url"]:
                                found = True
                                break
                        
                        if not found:
                            interesting[cat].append(snap)
                        break
        
        return interesting
    
    def scrape_page_content(self, wayback_url):
        try:
            response = self.session.get(wayback_url, timeout=15)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                
                info = {
                    "title": "",
                    "emails": [],
                    "phones": [],
                    "comments": [],
                    "forms": 0,
                    "links": []
                }
                
                title_tag = soup.find('title')
                if title_tag:
                    info["title"] = title_tag.text.strip()[:80]
                
                text_content = soup.get_text()
                
                email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
                emails = re.findall(email_pattern, text_content)
                info["emails"] = list(set(emails))[:5]
                
                phone_pattern = r'[\+\(]?[1-9][0-9 .\-\(\)]{8,}[0-9]'
                phones = re.findall(phone_pattern, text_content)
                info["phones"] = phones[:3]
                
                comment_pattern = r'<!--(.*?)-->'
                comments = re.findall(comment_pattern, str(soup), re.DOTALL)
                info["comments"] = [c.strip()[:80] for c in comments[:3] if c.strip()]
                
                forms = soup.find_all('form')
                info["forms"] = len(forms)
                
                links = soup.find_all('a', href=True)
                for link in links[:10]:
                    href = link.get('href', '')
                    if href and not href.startswith(('#', 'javascript:')):
                        info["links"].append(href[:100])
                
                return info
        except:
            pass
        
        return None
    
    def find_robots_txt(self):
        robots = []
        
        try:
            robot_url = f"https://web.archive.org/web/20200101000000*/{self.domain}/robots.txt"
            response = self.session.get(robot_url, timeout=15)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, 'html.parser')
                
                for link in soup.find_all('a', href=True):
                    href = link.get('href', '')
                    if 'robots.txt' in href and self.domain in href:
                        full_url = urljoin("https://web.archive.org", href)
                        
                        try:
                            robot_resp = self.session.get(full_url, timeout=10)
                            if robot_resp.status_code == 200:
                                content = robot_resp.text
                                
                                sitemaps = re.findall(r'sitemap:\s*(https?://[^\s]+)', content, re.I)
                                disallow = re.findall(r'disallow:\s*(/[^\s]*)', content, re.I)
                                allow = re.findall(r'allow:\s*(/[^\s]*)', content, re.I)
                                
                                if content.strip():
                                    robots.append({
                                        "url": full_url,
                                        "sitemaps": sitemaps[:2],
                                        "disallow": disallow[:5],
                                        "allow": allow[:5],
                                        "preview": content[:150]
                                    })
                                    break
                        except:
                            pass
        except:
            pass
        
        return robots
    
    def analyze_snapshots(self, snapshots):
        if len(snapshots) < 2:
            return []
        
        url_groups = {}
        for snap in snapshots:
            url = snap["url"]
            if url not in url_groups:
                url_groups[url] = []
            url_groups[url].append(snap)
        
        analysis = []
        for url, snaps in url_groups.items():
            if len(snaps) >= 2:
                snaps_sorted = sorted(snaps, key=lambda x: x["ts"])
                oldest = snaps_sorted[0]["ts"]
                newest = snaps_sorted[-1]["ts"]
                
                if oldest != newest:
                    analysis.append({
                        "url": url,
                        "первый": oldest[:8],
                        "последний": newest[:8],
                        "снимков": len(snaps)
                    })
        
        return analysis[:10]
    
    def run(self):
        print(f"\nначат сбор wayback для {self.domain}")
        print("подождите...")
        
        snapshots = self.get_cdx_data()
        
        if not snapshots:
            return {"ошибка": "нет данных для домена"}
        
        interesting = self.find_interesting_urls(snapshots)
        
        sample_content = None
        if snapshots:
            sample_snap = snapshots[0]
            sample_content = self.scrape_page_content(sample_snap["wayback"])
            time.sleep(1)
        
        robots = self.find_robots_txt()
        
        analysis = self.analyze_snapshots(snapshots)
        
        result = {
            "домен": self.domain,
            "всего_снимков": len(snapshots),
            "интересные_пути": {},
            "пример_контента": sample_content,
            "роботы": robots,
            "анализ": analysis,
            "дата": datetime.now().isoformat()
        }
        
        for cat, items in interesting.items():
            if items:
                result["интересные_пути"][cat] = []
                for item in items[:3]:
                    result["интересные_пути"][cat].append({
                        "url": item["url"],
                        "дата": item["ts"],
                        "wayback": item["wayback"]
                    })
        
        return result

def format_wayback_result(result):
    if "ошибка" in result:
        print(f"\nошибка: {result['ошибка']}")
        return
    
    domain = result.get("домен", "")
    total = result.get("всего_снимков", 0)
    
    print(f"\n{'='*60}")
    print(f"отчет wayback machine")
    print(f"{'='*60}")
    print(f"домен: {domain}")
    print(f"снимков: {total}")
    print(f"{'='*60}")
    
    interesting = result.get("интересные_пути", {})
    
    if interesting:
        print(f"\nнайдены интересные пути:")
        for cat, items in interesting.items():
            if items:
                print(f"\n{cat} ({len(items)}):")
                for i, item in enumerate(items, 1):
                    url_short = item['url'][:50] + "..." if len(item['url']) > 50 else item['url']
                    print(f"  {i}. {url_short}")
                    print(f"     📅 {item['дата'][:8]}")
    
    analysis = result.get("анализ", [])
    if analysis:
        print(f"\nисторические изменения:")
        for item in analysis[:3]:
            url_short = item['url'][:40] + "..." if len(item['url']) > 40 else item['url']
            print(f"  {url_short}")
            print(f"     с {item['первый']} по {item['последний']} ({item['снимков']} снимков)")
    
    robots = result.get("роботы", [])
    if robots:
        print(f"\nнайден robots.txt:")
        for robot in robots:
            if robot.get('disallow'):
                print(f"  запрещено: {', '.join(robot['disallow'][:3])}")
    
    sample = result.get("пример_контента")
    if sample:
        print(f"\nпример содержимого:")
        if sample.get("title"):
            print(f"  заголовок: {sample['title']}")
        if sample.get("emails"):
            print(f"  emails: {', '.join(sample['emails'][:2])}")
        if sample.get("forms") > 0:
            print(f"  форм на странице: {sample['forms']}")
    
    print(f"\n{'='*60}")
    print(f"что делать дальше:")
    
    if interesting:
        print("1. проверить найденные чувствительные пути")
    
    if analysis:
        print("2. сравнить разные версии страниц")
    
    if robots and any(r.get('disallow') for r in robots):
        print("3. проверить запрещенные пути на доступность")
    
    if total > 0:
        print(f"4. изучить {total} снимков полностью")
    
    print(f"{'='*60}")

def run_wayback():
    domain = input("введите домен для wayback -> ").strip().lower()
    
    if not domain or ' ' in domain:
        print("неверный домен")
        return
    
    scraper = wayback_scraper(domain)
    result = scraper.run()
    
    format_wayback_result(result)
    
    save = input("\nсохранить отчет? (y/n) -> ").lower()
    if save == 'y':
        import json
        filename = f"wayback_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"сохранено в {filename}")
    
    print(result)