from flask import Flask, render_template, request
import requests

app = Flask(__name__)

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "description": "Mitigates XSS attacks by controlling allowed resources",
        "recommendation": "default-src 'self'; object-src 'none'; script-src 'self'",
        "risk": "Without CSP, attackers can inject malicious scripts (XSS)."
    },
    "Strict-Transport-Security": {
        "description": "Enforces secure HTTPS connections",
        "recommendation": "max-age=63072000; includeSubDomains; preload",
        "risk": "Without HSTS, users may be vulnerable to man-in-the-middle attacks."
    },
    "X-Content-Type-Options": {
        "description": "Prevents MIME-type sniffing",
        "recommendation": "nosniff",
        "risk": "Without this, browsers may interpret files as a different MIME type, leading to XSS."
    },
    "X-Frame-Options": {
        "description": "Prevents clickjacking",
        "recommendation": "DENY or SAMEORIGIN",
        "risk": "Without this, your site can be embedded in iframes, enabling clickjacking."
    },
    "Referrer-Policy": {
        "description": "Controls referrer info sent to other sites",
        "recommendation": "no-referrer-when-downgrade",
        "risk": "Without this, sensitive URLs may be leaked via the Referer header."
    },
    "Permissions-Policy": {
        "description": "Restricts access to browser features",
        "recommendation": "geolocation=(), microphone=()",
        "risk": "Without this, sites may access features like camera or mic without restriction."
    },
    "Cross-Origin-Embedder-Policy": {
        "description": "Prevents insecure cross-origin embedding",
        "recommendation": "require-corp",
        "risk": "Without this, your site may be vulnerable to cross-origin attacks."
    },
    "Cross-Origin-Opener-Policy": {
        "description": "Enables site isolation and security context integrity",
        "recommendation": "same-origin",
        "risk": "Without this, your site may be vulnerable to cross-origin attacks."
    },
    "Cross-Origin-Resource-Policy": {
        "description": "Blocks resource sharing across origins",
        "recommendation": "same-origin",
        "risk": "Without this, resources may be shared with untrusted origins."
    },
    "Cache-Control": {
        "description": "Prevents sensitive data from being cached",
        "recommendation": "no-store",
        "risk": "Without this, sensitive data may be stored in browser/proxy caches."
    },
    "Set-Cookie": {
        "description": "Should use Secure, HttpOnly, and SameSite flags",
        "recommendation": "Set-Cookie: sessionid=abc; Secure; HttpOnly; SameSite=Strict",
        "risk": "Without these flags, cookies may be stolen via XSS or sent in cross-site requests (CSRF)."
    },
    "X-XSS-Protection": {
        "description": "Enables browser XSS filter (legacy)",
        "recommendation": "1; mode=block",
        "risk": "Without this, some browsers may not block reflected XSS attacks."
    },
    "X-Permitted-Cross-Domain-Policies": {
        "description": "Restricts Adobe Flash/Acrobat from loading data",
        "recommendation": "none",
        "risk": "Without this, Flash or Acrobat may access your data inappropriately."
    }
}

@app.route("/", methods=["GET", "POST"])
def index():
    results = {}
    error = None
    url = ""

    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if not url:
            error = "Please enter a URL."
        else:
            # Try https first, then http if https fails
            if not url.startswith("http"):
                test_urls = ["https://" + url, "http://" + url]
            else:
                test_urls = [url]
                if url.startswith("https://"):
                    test_urls.append(url.replace("https://", "http://", 1))
                elif url.startswith("http://"):
                    test_urls.append(url.replace("http://", "https://", 1))
            
            response = None
            for test_url in test_urls:
                try:
                    response = requests.get(test_url, timeout=5)
                    url = test_url  # Use the working URL
                    break
                except Exception as e:
                    last_error = str(e)
            if not response:
                error = f"Could not fetch the URL. Last error: {last_error}"
            else:
                headers = response.headers
                for header, meta in SECURITY_HEADERS.items():
                    value = headers.get(header)
                    if header == "Set-Cookie":
                        cookie = headers.get("Set-Cookie", "")
                        secure_flags = ["HttpOnly", "Secure", "SameSite"]
                        flags_present = all(flag in cookie for flag in secure_flags)
                        results[header] = {
                            "present": bool(cookie),
                            "value": cookie if cookie else "Not Set",
                            "ok": flags_present,
                            "description": meta["description"],
                            "recommendation": meta["recommendation"],
                            "risk": meta["risk"]
                        }
                    else:
                        results[header] = {
                            "present": bool(value),
                            "value": value if value else "Not Set",
                            "ok": bool(value),
                            "description": meta["description"],
                            "recommendation": meta["recommendation"],
                            "risk": meta["risk"]
                        }

    return render_template("index.html", results=results, error=error, url=url)

if __name__ == "__main__":
    app.run(debug=True)