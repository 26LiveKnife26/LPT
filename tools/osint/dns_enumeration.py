import socket
import dns.resolver
import dns.reversename
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

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
    console.print(Panel.fit(
        f"[bold cyan]DNS перечисление для: {domain}[/bold cyan]",
        border_style="cyan",
        box=box.ROUNDED
    ))
    
    # Таблица с основными DNS записями
    dns_table = Table(
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold cyan",
        border_style="cyan"
    )
    
    dns_table.add_column("Тип записи", style="bold white", width=15)
    dns_table.add_column("Значения", style="yellow", width=50)
    
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
    for rec in record_types:
        if rec in results and results[rec]:
            values = "\n".join(results[rec])
            dns_table.add_row(f"[green]{rec}[/green]", values)
        else:
            dns_table.add_row(f"[dim]{rec}[/dim]", "[dim]отсутствует[/dim]")
    
    console.print(dns_table)
    console.print()
    
    # Таблица поддоменов (как в примере)
    if 'поддомены' in results and results['поддомены']:
        sub_table = Table(
            title="[bold]Обнаруженные поддомены[/bold]",
            box=box.SIMPLE_HEAD,
            show_header=True,
            header_style="bold yellow",
            border_style="yellow"
        )
        
        sub_table.add_column("Поддомен", style="cyan", width=25)
        sub_table.add_column("Статус", justify="center", width=10)
        sub_table.add_column("IP адреса", style="green", width=25)
        
        for sub, ips in results['поддомены'].items():
            status = "[green]🟢[/green]" if ips else "[red]🔴 ---[/red]"
            ip_list = ", ".join(ips) if ips else "[dim](не найден)[/dim]"
            sub_table.add_row(sub, status, ip_list)
        
        console.print(sub_table)
    else:
        console.print("[dim]Поддомены не найдены[/dim]")
    
    console.print()
    
    # Таблица PTR записей
    if 'ptr_записи' in results and results['ptr_записи']:
        ptr_table = Table(
            title="[bold]PTR записи (обратный DNS)[/bold]",
            box=box.SIMPLE,
            show_header=True,
            header_style="bold magenta",
            border_style="magenta"
        )
        
        ptr_table.add_column("IP адрес", style="red", width=20)
        ptr_table.add_column("Статус", justify="center", width=10)
        ptr_table.add_column("Имя хоста", style="yellow", width=30)
        
        for ip, ptr in results['ptr_записи'].items():
            status = "[green]🟢[/green]" if ptr != "нет ptr записи" else "[red]🔴[/red]"
            hostname = ptr if ptr != "нет ptr записи" else "[dim]нет записи[/dim]"
            ptr_table.add_row(ip, status, hostname)
        
        console.print(ptr_table)
        console.print()
    
    # AXFR уязвимость
    if 'axfr_уязвимость' in results:
        axfr_status = results['axfr_уязвимость']
        
        vuln_table = Table(
            box=box.SIMPLE_HEAD,
            show_header=True,
            header_style="bold",
            border_style="red"
        )
        
        vuln_table.add_column("Проверка", style="white", width=25)
        vuln_table.add_column("Статус", justify="center", width=15)
        vuln_table.add_column("Результат", style="yellow", width=30)
        
        if isinstance(axfr_status, list) and axfr_status:
            vuln_table.add_row(
                "Zone Transfer (AXFR)", 
                "[bold red]🔴 УЯЗВИМО[/bold red]", 
                f"найдено {len(axfr_status)} записей"
            )
            
            console.print(vuln_table)
            console.print(Panel(
                "[bold red]⚠ ВНИМАНИЕ! Обнаружена уязвимость AXFR[/bold red]",
                border_style="red",
                box=box.DOUBLE
            ))
        else:
            vuln_table.add_row(
                "Zone Transfer (AXFR)", 
                "[bold green]🟢 БЕЗОПАСНО[/bold green]", 
                "[dim]не уязвимо[/dim]"
            )
            console.print(vuln_table)
    
    # Ошибки
    if 'ошибка' in results:
        error_table = Table(
            box=box.SIMPLE_HEAD,
            show_header=False,
            border_style="red"
        )
        
        error_table.add_column("", style="red", width=70)
        error_table.add_row(f"[bold red]✗ Ошибка:[/bold red] {results['ошибка']}")
        
        console.print(error_table)