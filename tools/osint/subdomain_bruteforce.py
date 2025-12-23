import asyncio
import aiohttp
import socket

async def check_subdomain(session, subdomain, domain, timeout=3):
    full_domain = f"{subdomain}.{domain}"
    
    try:
        ip = socket.gethostbyname(full_domain)
        
        protocols = [f"http://{full_domain}", f"https://{full_domain}"]
        for url in protocols:
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout), ssl=False) as response:
                    if response.status < 400:
                        return (full_domain, ip, response.status, "active")
            except:
                pass
        
        return (full_domain, ip, 0, "dns_only")
    except:
        return None

async def subdomain_bruteforce(domain, wordlist=None, max_concurrent=100):
    if wordlist is None:
        wordlist = [
            'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'blog', 'panel',
            'webmail', 'portal', 'cdn', 'static', 'assets', 'img', 'images',
            'shop', 'store', 'app', 'mobile', 'm', 'support', 'help', 'docs',
            'status', 'monitor', 'stats', 'analytics', 'crm', 'erp', 'vpn',
            'secure', 'auth', 'login', 'signin', 'owa', 'exchange', 'remote',
            'ns1', 'ns2', 'dns1', 'dns2', 'mx1', 'mx2', 'smtp', 'pop', 'imap',
            'git', 'svn', 'jenkins', 'ci', 'staging', 'prod', 'beta', 'alpha'
        ]
    
    found = []
    connector = aiohttp.TCPConnector(limit=max_concurrent, ssl=False)
    
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = []
        for sub in wordlist:
            task = asyncio.create_task(check_subdomain(session, sub, domain))
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
    
    for result in results:
        if result and not isinstance(result, Exception):
            found.append(result)
    
    return found

def run_bruteforce(domain):
    print(f"запускаю brute force поддоменов для {domain}...")
    print("это может занять некоторое время...")
    
    results = asyncio.run(subdomain_bruteforce(domain))
    
    if results:
        print(f"\nнайдено {len(results)} поддоменов:")
        print("-" * 50)
        
        active = [r for r in results if r[3] == "active"]
        dns_only = [r for r in results if r[3] == "dns_only"]
        
        if active:
            print("\nактивные поддомены (отвечают на http/https):")
            for sub, ip, status, _ in active:
                print(f"  {sub} -> {ip} [статус: {status}]")
        
        if dns_only:
            print("\nтолько dns записи:")
            for sub, ip, _, _ in dns_only:
                print(f"  {sub} -> {ip}")
        
        print(f"\nстатистика: активные - {len(active)}, только dns - {len(dns_only)}")
    else:
        print("поддомены не найдены")
    
    return results