import asyncio
import aiohttp
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from bs4 import BeautifulSoup
import re
import json
from datetime import datetime

class xss_scanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.results = {
            "уязвимые_формы": [],
            "уязвимые_параметры": [],
            "рефлексы": [],
            "потенциальные_xss": [],
            "отсканированные_страницы": [],
            "статистика": {
                "всего_форм": 0,
                "всего_параметров": 0,
                "найдено_xss": 0,
                "рефлектирующие_параметры": 0
            }
        }
        
        self.payloads = [
            "<script>alert('xss')</script>",
            "\"><script>alert('xss')</script>",
            "'><script>alert('xss')</script>",
            "javascript:alert('xss')",
            "onload=alert('xss')",
            "onerror=alert('xss')",
            "onmouseover=alert('xss')",
            "onfocus=alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "<svg/onload=alert('xss')>",
            "<iframe src=javascript:alert('xss')>",
            "<body onload=alert('xss')>",
            "<input onfocus=alert('xss') autofocus>",
            "<details open ontoggle=alert('xss')>",
            "<select onfocus=alert('xss') autofocus>",
            "<textarea onfocus=alert('xss') autofocus>",
            "<keygen onfocus=alert('xss') autofocus>"
        ]
    
    async def fetch_page(self, url):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, ssl=False, timeout=10) as response:
                    if response.status == 200:
                        return await response.text()
        except:
            pass
        return None
    
    async def test_form_xss(self, form_info, page_url):
        try:
            action_url = form_info["action"]
            if not action_url.startswith(('http://', 'https://')):
                action_url = urljoin(page_url, action_url)
            
            method = form_info["method"].lower()
            inputs = form_info["inputs"]
            
            if not inputs:
                return None
            
            for payload in self.payloads[:5]:
                test_data = {}
                
                for inp in inputs:
                    input_name = inp["name"]
                    if inp["type"] in ["text", "textarea", "search", "email", "url"]:
                        test_data[input_name] = payload
                    else:
                        test_data[input_name] = inp.get("value", "test")
                
                async with aiohttp.ClientSession() as session:
                    if method == "get":
                        params = urlencode(test_data)
                        test_url = f"{action_url}?{params}"
                        async with session.get(test_url, ssl=False, timeout=15) as response:
                            content = await response.text()
                    else:
                        async with session.post(action_url, data=test_data, ssl=False, timeout=15) as response:
                            content = await response.text()
                    
                    if self.check_payload_reflection(content, payload):
                        return {
                            "форма_url": page_url,
                            "action_url": action_url,
                            "метод": method,
                            "payload": payload,
                            "поле_с_payload": next((inp["name"] for inp in inputs if inp["type"] in ["text", "textarea", "search"]), "неизвестно")
                        }
        except:
            pass
        
        return None
    
    async def test_parameter_xss(self, url):
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        if not query_params:
            return []
        
        vulnerable_params = []
        
        for param_name in query_params.keys():
            for payload in self.payloads[:3]:
                test_params = query_params.copy()
                test_params[param_name] = [payload]
                
                test_query = urlencode(test_params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{test_query}"
                
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(test_url, ssl=False, timeout=15) as response:
                            content = await response.text()
                            
                            if self.check_payload_reflection(content, payload):
                                vulnerable_params.append({
                                    "параметр": param_name,
                                    "payload": payload,
                                    "test_url": test_url[:100] + "..." if len(test_url) > 100 else test_url,
                                    "рефлектирует": True
                                })
                except:
                    pass
        
        return vulnerable_params
    
    def check_payload_reflection(self, content, payload):
        clean_payload = payload.replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#x27;')
        
        if payload in content:
            return True
        
        if clean_payload in content:
            return True
        
        payload_no_tags = re.sub(r'<[^>]+>', '', payload)
        if payload_no_tags and payload_no_tags in content:
            return True
        
        return False
    
    def find_reflective_params(self, url, content):
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        
        reflective = []
        
        for param_name, param_values in query_params.items():
            for value in param_values:
                if value and value in content:
                    reflective.append({
                        "параметр": param_name,
                        "значение": value[:50],
                        "рефлектирует": True,
                        "url": url[:80] + "..." if len(url) > 80 else url
                    })
        
        return reflective
    
    def extract_forms(self, html, page_url):
        soup = BeautifulSoup(html, 'html.parser')
        forms = []
        
        for form in soup.find_all('form'):
            form_info = {
                "action": form.get('action', ''),
                "method": form.get('method', 'get').lower(),
                "inputs": []
            }
            
            if not form_info["action"]:
                form_info["action"] = page_url
            
            for inp in form.find_all(['input', 'textarea', 'select']):
                input_type = inp.get('type', 'text')
                input_name = inp.get('name', '')
                
                if input_name:
                    form_info["inputs"].append({
                        "name": input_name,
                        "type": input_type,
                        "value": inp.get('value', '')
                    })
            
            if form_info["inputs"]:
                forms.append(form_info)
        
        return forms
    
    async def crawl_for_forms_and_params(self, start_url, max_pages=10):
        visited = set()
        to_visit = [start_url]
        
        pages_scanned = 0
        
        while to_visit and pages_scanned < max_pages:
            url = to_visit.pop(0)
            
            if url in visited:
                continue
            
            visited.add(url)
            pages_scanned += 1
            
            print(f"сканирую [{pages_scanned}/{max_pages}]: {url[:60]}...")
            
            html = await self.fetch_page(url)
            
            if not html:
                continue
            
            page_info = {
                "url": url,
                "формы": [],
                "параметры": [],
                "рефлексы": []
            }
            
            forms = self.extract_forms(html, url)
            page_info["формы"] = [{"action": f["action"], "inputs_count": len(f["inputs"])} for f in forms]
            
            for form in forms:
                self.results["статистика"]["всего_форм"] += 1
                result = await self.test_form_xss(form, url)
                if result:
                    self.results["уязвимые_формы"].append(result)
                    self.results["статистика"]["найдено_xss"] += 1
            
            param_results = await self.test_parameter_xss(url)
            page_info["параметры"] = [{"параметр": p["параметр"], "уязвим": True} for p in param_results]
            
            if param_results:
                self.results["уязвимые_параметры"].extend(param_results)
                self.results["статистика"]["найдено_xss"] += len(param_results)
            
            reflective = self.find_reflective_params(url, html)
            page_info["рефлексы"] = reflective
            self.results["рефлексы"].extend(reflective)
            self.results["статистика"]["рефлектирующие_параметры"] += len(reflective)
            
            self.results["отсканированные_страницы"].append(page_info)
            
            soup = BeautifulSoup(html, 'html.parser')
            for link in soup.find_all('a', href=True):
                href = link.get('href')
                if href and href.startswith(('http://', 'https://')):
                    parsed = urlparse(href)
                    target_parsed = urlparse(start_url)
                    
                    if parsed.netloc == target_parsed.netloc and href not in visited:
                        to_visit.append(href)
            
            await asyncio.sleep(0.5)
    
    def print_results(self):
        print(f"\n{'='*80}")
        print(f"🔍 отчет xss сканирования: {self.target_url}")
        print(f"{'='*80}")
        
        stats = self.results["статистика"]
        print(f"\n📊 статистика:")
        print(f"   отсканировано страниц: {len(self.results['отсканированные_страницы'])}")
        print(f"   проверено форм: {stats['всего_форм']}")
        print(f"   рефлектирующих параметров: {stats['рефлектирующие_параметры']}")
        print(f"   найдено xss уязвимостей: {stats['найдено_xss']}")
        
        print(f"\n{'='*80}")
        
        if self.results["уязвимые_формы"]:
            print(f"\n🎯 уязвимые формы ({len(self.results['уязвимые_формы'])}):")
            for i, vuln in enumerate(self.results["уязвимые_формы"][:5], 1):
                print(f"   {i}. форма на странице: {vuln['форма_url'][:50]}...")
                print(f"      метод: {vuln['метод']}, поле: {vuln['поле_с_payload']}")
                print(f"      payload: {vuln['payload'][:40]}...")
                print(f"      action: {vuln['action_url'][:60]}...")
        
        if self.results["уязвимые_параметры"]:
            print(f"\n🎯 уязвимые параметры url ({len(self.results['уязвимые_параметры'])}):")
            for i, vuln in enumerate(self.results["уязвимые_параметры"][:5], 1):
                print(f"   {i}. параметр: {vuln['параметр']}")
                print(f"      payload: {vuln['payload'][:40]}...")
                print(f"      test url: {vuln['test_url']}")
        
        if self.results["рефлексы"]:
            print(f"\n🪞 рефлектирующие параметры ({len(self.results['рефлексы'])}):")
            seen = set()
            for i, refl in enumerate(self.results["рефлексы"][:5], 1):
                key = (refl['параметр'], refl['значение'])
                if key not in seen:
                    seen.add(key)
                    print(f"   {i}. {refl['параметр']} = {refl['значение']}")
                    print(f"      url: {refl['url']}")
        
        print(f"\n{'='*80}")
        print(f"💡 рекомендации:")
        
        if self.results["уязвимые_формы"] or self.results["уязвимые_параметры"]:
            print("   1. все найденные уязвимости требуют фиксации")
            print("   2. провести мануальное тестирование для подтверждения")
            print("   3. проверить другие похожие формы и параметры")
        
        if self.results["рефлексы"] and not self.results["уязвимые_формы"] and not self.results["уязвимые_параметры"]:
            print("   1. рефлектирующие параметры есть, но xss не найдены")
            print("   2. попробовать более сложные payloads")
            print("   3. проверить фильтрацию на стороне клиента")
        
        if not any([self.results["уязвимые_формы"], self.results["уязвимые_параметры"], self.results["рефлексы"]]):
            print("   1. xss уязвимостей не найдено (хороший результат)")
            print("   2. провести более глубокое тестирование вручную")
        
        print(f"\n{'='*80}")
        
        if self.results["отсканированные_страницы"]:
            print(f"\n📄 примеры отсканированных страниц:")
            for page in self.results["отсканированные_страницы"][:3]:
                print(f"   🌐 {page['url'][:60]}...")
                print(f"      форм: {len(page['формы'])}, параметров: {len(page['параметры'])}")
        
        print(f"\n{'='*80}")
        print(f"⏱ сканирование завершено: {datetime.now().strftime('%H:%M:%S')}")
        print(f"{'='*80}")

async def run_xss_scanner():
    target = input("\nвведите url для xss сканирования -> ").strip()
    
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    
    max_pages = input("максимум страниц для сканирования (по умолчанию 10) -> ").strip()
    max_pages = int(max_pages) if max_pages.isdigit() else 10
    
    print(f"\nначато xss сканирование {target}")
    print(f"максимум страниц: {max_pages}")
    print("подождите...")
    
    scanner = xss_scanner(target)
    await scanner.crawl_for_forms_and_params(target, max_pages)
    
    scanner.print_results()
    
    save = input("\nсохранить отчет? (y/n) -> ").lower()
    if save == 'y':
        filename = f"xss_report_{urlparse(target).netloc}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(scanner.results, f, indent=2, ensure_ascii=False)
        print(f"отчет сохранен в {filename}")
