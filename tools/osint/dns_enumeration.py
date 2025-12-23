import socket
import dns.resolver
import dns.reversename

def dns_enum(domain):
    results = {}
    
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '1.1.1.1']
        
        records = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        for rec in records:
            try:
                answer = resolver.resolve(domain, rec)
                results[rec] = [str(r) for r in answer]
            except:
                results[rec] = []
        
        common_subs = ['www', 'mail', 'ftp', 'admin', 'test', 'dev', 'api', 'blog']
        found_subs = {}
        for sub in common_subs:
            try:
                target = f"{sub}.{domain}"
                answer = resolver.resolve(target, 'A')
                found_subs[target] = [str(r) for r in answer]
            except:
                pass
        results['поддомены'] = found_subs
        
        try:
            ptr_info = {}
            for ip in results.get('A', []):
                try:
                    rev = dns.reversename.from_address(ip)
                    answer = resolver.resolve(rev, 'PTR')
                    ptr_info[ip] = str(answer[0])
                except:
                    ptr_info[ip] = "нет ptr записи"
            if ptr_info:
                results['ptr_записи'] = ptr_info
        except:
            pass
        
        try:
            answer = resolver.resolve(domain, 'AXFR')
            results['axfr_уязвимость'] = [str(r) for r in answer]
        except:
            results['axfr_уязвимость'] = "не уязвимо"
        
    except Exception as e:
        results['ошибка'] = str(e)
    
    return results

def print_dns_results(results, domain):
    print(f"\n{'='*50}")
    print(f"результаты dns перечисления для: {domain}")
    print(f"{'='*50}\n")
    
    for record_type, data in results.items():
        if record_type == 'ошибка':
            print(f"[!] ошибка: {data}\n")
            continue
            
        print(f"[+] {record_type}:")
        
        if record_type == 'поддомены':
            if data:
                for sub, ips in data.items():
                    print(f"    ├─ {sub}: {', '.join(ips)}")
            else:
                print("    ├─ поддомены не найдены")
        
        elif record_type == 'ptr_записи':
            for ip, ptr in data.items():
                print(f"    ├─ {ip} -> {ptr}")
        
        elif record_type == 'axfr_уязвимость':
            if isinstance(data, list) and data:
                print("    ├─ обнаружена уязвимость zone transfer!")
                for record in data:
                    print(f"    │  └─ {record}")
            else:
                print(f"    ├─ {data}")
        
        elif isinstance(data, list) and data:
            for item in data:
                print(f"    ├─ {item}")
        else:
            print(f"    ├─ записи отсутствуют")
        
        print()
        