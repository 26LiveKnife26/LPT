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
    
    def print_results(self, snapshots, interesting, sample_content, robots, analysis):
        print(f"\n{'='*70}")
        print(f"📜 отчет wayback machine для {self.domain}")
        print(f"{'='*70}")
        
        print(f"\n📊 общая информация:")
        print(f"   всего снимков: {len(snapshots)}")
        print(f"   дата анализа: {datetime.now().strftime('%d.%m.%Y %H:%M')}")
        
        print(f"\n{'='*70}")
        print(f"🔍 найденные интересные пути:")
        
        found_any = False
        for cat, items in interesting.items():
            if items:
                found_any = True
                print(f"\n   📁 {cat} ({len(items)}):")
                for i, item in enumerate(items[:3], 1):
                    url_short = item['url']
                    if len(url_short) > 50:
                        url_short = url_short[:47] + "..."
                    print(f"      {i}. {url_short}")
                    print(f"          📅 {item['ts'][:8]} | {item['wayback'][:60]}...")
        
        if not found_any:
            print("   😕 интересные пути не найдены")
        
        print(f"\n{'='*70}")
        print(f"🕰 исторические изменения:")
        
        if analysis:
            for item in analysis[:3]:
                url_short = item['url']
                if len(url_short) > 45:
                    url_short = url_short[:42] + "..."
                print(f"\n   🔄 {url_short}")
                print(f"      📅 первый снимок: {item['первый']}")
                print(f"      📅 последний снимок: {item['последний']}")
                print(f"      🖼 всего снимков: {item['снимков']}")
        else:
            print("   📊 недостаточно данных для анализа изменений")
        
        print(f"\n{'='*70}")
        print(f"🤖 robots.txt информация:")
        
        if robots:
            for robot in robots[:2]:
                print(f"\n   📄 найден robots.txt:")
                if robot.get('disallow'):
                    print(f"      🚫 запрещенные пути:")
                    for path in robot['disallow'][:3]:
                        print(f"         • {path}")
                if robot.get('sitemaps'):
                    print(f"      🗺 sitemaps:")
                    for sitemap in robot['sitemaps'][:2]:
                        print(f"         • {sitemap}")
        else:
            print("   🤷 robots.txt не найден")
        
        print(f"\n{'='*70}")
        print(f"📄 пример содержимого снимка:")
        
        if sample_content:
            print(f"\n   📌 заголовок: {sample_content.get('title', 'не найден')}")
            
            if sample_content.get('emails'):
                print(f"   📧 найденные email:")
                for email in sample_content['emails'][:3]:
                    print(f"      • {email}")
            
            if sample_content.get('phones'):
                print(f"   📞 найденные телефоны:")
                for phone in sample_content['phones'][:2]:
                    print(f"      • {phone}")
            
            if sample_content.get('forms', 0) > 0:
                print(f"   📝 форм на странице: {sample_content['forms']}")
            
            if sample_content.get('comments'):
                print(f"   💬 html комментарии:")
                for comment in sample_content['comments'][:2]:
                    print(f"      • {comment}")
        else:
            print("   😕 не удалось получить содержимое")
        
        print(f"\n{'='*70}")
        print(f"💡 рекомендации:")
        
        recommendations = []
        
        if interesting and any(len(items) > 0 for items in interesting.values()):
            recommendations.append("проверить найденные чувствительные пути на уязвимости")
        
        if analysis:
            recommendations.append("сравнить разные версии страниц для поиска изменений")
        
        if robots and any(r.get('disallow') for r in robots):
            recommendations.append("проверить запрещенные пути из robots.txt на доступность")
        
        if len(snapshots) > 20:
            recommendations.append(f"изучить все {len(snapshots)} снимков для полного анализа")
        
        if recommendations:
            for i, rec in enumerate(recommendations, 1):
                print(f"   {i}. {rec}")
        else:
            print("   🤔 рекомендаций нет - данных слишком мало")
        
        print(f"\n{'='*70}")
    
    def run_and_print(self):
        print(f"\nначат сбор wayback для {self.domain}")
        print("подождите...")
        
        snapshots = self.get_cdx_data()
        
        if not snapshots:
            print(f"\n{'='*70}")
            print(f"😕 ошибка: нет данных wayback для домена {self.domain}")
            print(f"возможно домен не индексировался или заблокирован")
            print(f"{'='*70}")
            return
        
        interesting = self.find_interesting_urls(snapshots)
        
        sample_content = None
        if snapshots:
            sample_snap = snapshots[0]
            sample_content = self.scrape_page_content(sample_snap["wayback"])
            time.sleep(1)
        
        robots = self.find_robots_txt()
        
        analysis = self.analyze_snapshots(snapshots)
        
        self.print_results(snapshots, interesting, sample_content, robots, analysis)

def run_wayback_scraper():
    domain = input("\nвведите домен для wayback machine -> ").strip().lower()
    
    if not domain or ' ' in domain:
        print("неверный формат домена")
        return
    
    scraper = wayback_scraper(domain)
    scraper.run_and_print()
    
    save = input("\nсохранить сырые данные? (y/n) -> ").lower()
    if save == 'y':
        try:
            import json
            filename = f"wayback_{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            
            result_data = {
                "domain": domain,
                "snapshots_count": len(scraper.get_cdx_data()),
                "timestamp": datetime.now().isoformat()
            }
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(result_data, f, indent=2, ensure_ascii=False)
            print(f"данные сохранены в {filename}")
        except:
            print("ошибка при сохранении")
