import asyncio
import socket
from datetime import datetime

async def check_port(ip, port, timeout=1):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )
        writer.close()
        await writer.wait_closed()
        
        try:
            service = socket.getservbyport(port)
        except:
            service = "unknown"
        
        return port, "open", service
    except:
        return port, "closed", None

async def grab_banner(ip, port, timeout=2):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )
        
        await asyncio.sleep(0.5)
        writer.write(b"\r\n")
        await writer.drain()
        
        banner = await asyncio.wait_for(reader.read(1024), timeout=1)
        writer.close()
        await writer.wait_closed()
        
        return banner.decode('utf-8', errors='ignore').strip()
    except:
        return None

async def scan_ports(ip, ports, max_concurrent=200, get_banners=False):
    open_ports = []
    
    semaphore = asyncio.Semaphore(max_concurrent)
    
    async def scan_with_semaphore(port):
        async with semaphore:
            return await check_port(ip, port)
    
    tasks = [scan_with_semaphore(port) for port in ports]
    results = await asyncio.gather(*tasks)
    
    for port, status, service in results:
        if status == "open":
            banner = None
            if get_banners:
                banner = await grab_banner(ip, port)
            open_ports.append({
                "port": port,
                "service": service,
                "banner": banner,
                "status": status
            })
    
    return open_ports

def parse_port_range(port_range):
    ports = []
    if "-" in port_range:
        start, end = map(int, port_range.split("-"))
        ports = list(range(start, end + 1))
    elif "," in port_range:
        ports = [int(p) for p in port_range.split(",")]
    else:
        ports = [int(port_range)]
    return ports

async def port_scan(target, port_range="1-1024", max_concurrent=200, get_banners=False):
    try:
        ip = socket.gethostbyname(target)
        resolved_from = target if target != ip else None
    except socket.gaierror:
        return {
            "error": f"не удалось разрешить домен: {target}",
            "target": target,
            "resolved_ip": None
        }
    
    start_time = datetime.now()
    ports = parse_port_range(port_range)
    open_ports = await scan_ports(ip, ports, max_concurrent, get_banners)
    end_time = datetime.now()
    scan_time = (end_time - start_time).total_seconds()
    
    return {
        "target": target,
        "resolved_ip": ip,
        "resolved_from": resolved_from,
        "scan_time": scan_time,
        "total_ports": len(ports),
        "open_ports_count": len(open_ports),
        "open_ports": open_ports,
        "timestamp": datetime.now().isoformat()
    }

def run_scanner(target, port_range="1-1024", max_concurrent=200, get_banners=False):
    return asyncio.run(port_scan(target, port_range, max_concurrent, get_banners))