import sys
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse



def print_banner():
    banned_text = r'''
   d8,                   d8b         d8,       
  `8P                    ?88        `8P        
                          88b                  
  d88   d888b8b   d8888b  888  d88'  88b d8888b
  ?88  d8P' ?88  d8P' `P  888bd8P'   88Pd8b_,dP
   88b 88b  ,88b 88b     d88888b    d88 88b    
   `88b`?88P'`88b`?888P'd88' `?88b,d88' `?888P'
    )88                                        
   ,88P                                        
`?888P                                         

Version: 1.0
Developer: 1day
'''
    print(banned_text)
    print("="*40)
    print()


def clickjacking(session, url):
    try:
        response = session.head(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36"}, timeout=5)
        return evaluateResponse(url, response)
    except (requests.exceptions.RequestException, requests.exceptions.HTTPError):
        url_http = url.replace("https://", "http://")
        try:
            response = session.head(url_http, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36"}, timeout=5)
            return evaluateResponse(url_http, response)
        except requests.exceptions.RequestException:
            return url_http, False

def evaluateResponse(url, response):
    if response.status_code != 200:
        return url, False  # Not vulnerable

    headers = {k.lower(): v for k, v in response.headers.items()}

    x_frame_options = headers.get('x-frame-options', '').lower()
    content_security_policy = headers.get('content-security-policy', '').lower()
    x_frame_options_set = set(x_frame_options.split(',')) # Some ALBs add same header again resulting in duplicates, so we get only 1 here.

    is_vulnerable = True

    if any(option.strip() in ['sameorigin', 'deny'] for option in x_frame_options_set):
        is_vulnerable = False

    if "frame-ancestors" in content_security_policy:
        is_vulnerable = False

    return url, is_vulnerable 


def is_valid(url):
    return url.startswith(('http://', 'https://'))


def main():
    print_banner()
    parser = argparse.ArgumentParser(description="Check URLs for clickjacking vulnerabilities.")
    parser.add_argument("-o", "--output", help="Output file for vulnerable URLs")

    args = parser.parse_args()

    if not sys.stdin.isatty():
        urls = [line.strip() for line in sys.stdin if line.strip()]
        for url in urls:
            if not is_valid(url):
                print(f"Error: Invalid URL '{url}'. Please provide fully qualified URLs (with http:// or https://).")
                sys.exit(1)

        with requests.Session() as session:
            with ThreadPoolExecutor(max_workers=1000) as executor: 
                futures = {executor.submit(clickjacking, session, url): url for url in urls}
                vulnerable_urls = []

                for future in as_completed(futures):
                    result, is_vulnerable = future.result()
                    if result is not None: 
                        if is_vulnerable:
                            print(f"\033[32m[1] VULNERABLE - {result}\033[0m") 
                            vulnerable_urls.append(result) 
                        else:
                            print(f"\033[31m[0] NOT VULNERABLE - {result}\033[0m") 

                if args.output:
                    with open(args.output, 'w') as f:
                        for url in vulnerable_urls:
                            f.write(url + '\n')

    else:
        print("Usage: cat <file_with_urls> | python3 jackie.py [-o <output_file>]")
        sys.exit(1)

if __name__ == "__main__":
    main()