import requests

# These are the headers we're checking for, with descriptions
SECURITY_HEADERS = {
    "Content-Security-Policy": "Mitigates XSS attacks by controlling allowed resources",
    "Strict-Transport-Security": "Enforces secure HTTPS connections",
    "X-Content-Type-Options": "Prevents MIME-type sniffing (set to 'nosniff')",
    "X-Frame-Options": "Prevents clickjacking by controlling iframe use",
    "Referrer-Policy": "Limits referrer information sent to other sites",
    "Permissions-Policy": "Restricts access to browser features (camera, mic, etc.)"
}

def analyze_headers(url):
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        print(f"\nAnalyzing security headers for: {url}\n")

        for header, description in SECURITY_HEADERS.items():
            value = headers.get(header)
            if value:
                print(f"[+] {header}: FOUND ✅ — Value: {value}")
            else:
                print(f"[-] {header}: MISSING ❌ — {description}")

    except requests.exceptions.RequestException as e:
        print(f"❌ Error fetching {url}: {e}")

if __name__ == "__main__":
    url = input("Enter URL (e.g., https://dfwcommonground.com): ").strip()
    analyze_headers(url)