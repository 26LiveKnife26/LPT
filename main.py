from tools.gui import script_messages
import simple_term_menu
import art
import json
import random
import time
import sys
from tools.osint import whois_lookup, dns_enumeration, subdomain_bruteforce, port_scaner, banner_identifier, leaks

with open('backend/cookies.json', 'r') as cookies:
    cookie = json.load(cookies)

art.tprint("*   LPT   *")

if cookie["user"]["first?"] == "yes":
    print("вы впервые, не хотели ли бы вы прочитать инструкцию?")
    choice_index = simple_term_menu.TerminalMenu(
        ["да", "нет"],
        menu_cursor="→ ",
        clear_screen=False
    ).show()
    
    if choice_index == 0:
        print("инструкция:\n1.для использования модуля нажмите w или выберите пункт в меню\n2.если вы не знаете применение какому либо модулю нажмите h или выберите соответсвующий пункт в меню\n3.если вы нашли баг то обратитесь на почту liveknife26@gmail.com. либо откройте issue/discussion в github\nудачной работы!")
        input("\nнажмите enter для продолжения...")
        
    cookie["user"]["first?"] = "no"
    with open('backend/cookies.json', 'w') as cookies:
        json.dump(cookie, cookies, indent=4)

print(script_messages.loading)
time.sleep(random.randint(5, 10))
print("\033c\033[3J", end="")

while True:
    print(script_messages.welcome)
    print("")
    
    menu = simple_term_menu.TerminalMenu(
        ["модули", "логи", "генератор отчетов", "выход"],
        menu_cursor="-> ",
        menu_cursor_style=("fg_gray", "bold"),
        clear_screen=False
    ).show()
    
    if menu == 0:
        print("\033c\033[3J", end="")
        print("модули 📦")
        print("")
        modules_menu = simple_term_menu.TerminalMenu(
            ["osint", "веб-пентест", "крипто и сети", "эксплуатация", "назад"],
            menu_cursor="-> ",
            menu_cursor_style=("fg_gray", "bold"),
            clear_screen=False
        ).show()
        if modules_menu == 0:
            osint_menu = simple_term_menu.TerminalMenu(
                ["whois lookup", "dns enumeration", "brute force(subdomain)", "port-scaner", "определение сервиса по баннеру", "сбор информации", "wayback-machine(скрейпер)"],
                menu_cursor="-> ",
                menu_cursor_style=("fg_gray", "bold"),
                clear_screen=False
            ).show()
            if osint_menu == 0:
                osint_domen_whois = input("домен сайта(без https://) -> ")
                print(whois_lookup.whois_lookup(osint_domen_whois))
                input("")
            elif osint_menu == 1:
                osint_domen_dns = input("домен сайта(без https://) -> ")
                dns_enumeration.print_dns_results(dns_enumeration.dns_enum(osint_domen_dns), osint_domen_dns)
            elif osint_menu == 2:
                osint_domen_brute = input("домен сайта(без https://) -> ")
                try:
                    results = subdomain_bruteforce.run_bruteforce(osint_domen_brute)
                    
                    save = input("сохранить результаты в файл? (y/n) -> ").lower()
                    if save == 'y':
                        import json
                        from datetime import datetime
                        
                        filename = f"results/subdomains_{osint_domen_brute}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                        data = {
                            "domain": osint_domen_brute,
                            "timestamp": datetime.now().isoformat(),
                            "results": [list(r) for r in results]
                        }
                        
                        with open(filename, 'w', encoding='utf-8') as f:
                            json.dump(data, f, indent=4, ensure_ascii=False)
                        print(f"результаты сохранены в {filename}")
                except ImportError:
                    print("модуль subdomain_bruteforce не найден")
                except Exception as e:
                    print(f"ошибка: {e}")
                input("")
            elif osint_menu == 3:
                osint_domen_portscan = input("введите IP сайта или домен -> ")
                osint_domen_portscan_ports = input("введите кол-во портов(1-1024) -> ")
                osint_domen_portscan_banners = int(input("включить баннеры?(1- да, 2 - нет) -> "))
                if osint_domen_portscan_banners == 1:
                    osint_domen_portscan_banners_status = True
                else:
                    osint_domen_portscan_banners_status = False
                results = port_scaner.run_scanner(osint_domen_portscan, osint_domen_portscan_ports, 1024, osint_domen_portscan_banners_status)

                print(f"сканирование {results['target']}")
                print(f"время: {results['scan_time']:.2f} сек")
                print(f"портов: {results['total_ports']}")
                print(f"открыто: {results['open_ports_count']}")

                input()
                for port_info in results["open_ports"]:
                    print(f"{port_info['port']} - {port_info['service']}")
                    if port_info['banner']:
                        print(f"  баннер: {port_info['banner'][:50]}")
                input()
            elif osint_menu == 4:
                results = banner_identifier.run_fast_banner_scan()
                
                save = input("\nсохранить результаты? (y/n) -> ").lower()
                if save == 'y':
                    import json
                    from datetime import datetime
                    
                    filename = f"results/banner_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                    with open(filename, 'w', encoding='utf-8') as f:
                        json.dump(results, f, indent=4, ensure_ascii=False)
                    print(f"результаты сохранены в {filename}")
                
                input()
            elif osint_menu == 5:
                leaks.run_advanced_osint()
    elif menu == 1:
        print("логи еще в разработке, иди нафиг")
        input("")
    
    elif menu == 2:
        print("генератор отчетов еще в разработке, иди нафиг")
        input("")
    
    elif menu == 3:
        print("проваливай!")
        sys.exit()
    
    print("\033c\033[3J", end="")