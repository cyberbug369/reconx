import re
import socket
import urllib.error
import urllib.parse
import urllib.request


SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "Content Security Policy",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}


def normalize_url(target):
    """Ensure the target has an HTTP scheme."""

    target = target.strip()

    if target.startswith(("http://", "https://")):
        return target

    return f"https://{target}"


def resolve_ipv4(hostname):
    """Resolve a hostname to IPv4 addresses."""

    try:
        results = socket.getaddrinfo(
            hostname,
            443,
            socket.AF_INET,
            socket.SOCK_STREAM,
        )

        return sorted(
            set(result[4][0] for result in results)
        )

    except socket.gaierror:
        return []


def fetch_page(target):
    """Fetch a web page using a normal GET request."""

    url = normalize_url(target)

    request = urllib.request.Request(
        url,
        method="GET",
        headers={
            "User-Agent": "RECONX/0.2.0",
            "Accept": "text/html,application/xhtml+xml,*/*",
        },
    )

    with urllib.request.urlopen(
        request,
        timeout=15,
    ) as response:

        raw_body = response.read(500_000)

        body = raw_body.decode(
            "utf-8",
            errors="ignore",
        )

        return response, body, len(raw_body)


def inspect_headers(target):
    """Inspect HTTP response headers."""

    url = normalize_url(target)
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname

    print("\nRECONX HTTP HEADER INSPECTOR")
    print("────────────────────────────────")
    print(f"Target: {url}")

    if not hostname:
        print("\n[!] Invalid target.")
        return

    ipv4_addresses = resolve_ipv4(hostname)

    if ipv4_addresses:
        print(f"IPv4  : {', '.join(ipv4_addresses)}")
    else:
        try:
            fallback_ip = socket.gethostbyname(hostname)
            print(f"IPv4  : {fallback_ip}")
        except socket.gaierror:
            print(f"\n[!] Unable to resolve: {hostname}")
            return

    request = urllib.request.Request(
        url,
        method="GET",
        headers={
            "User-Agent": "RECONX/0.2.0",
            "Accept": "*/*",
        },
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=15,
        ) as response:

            print(f"Status: {response.status}")

            headers = response.headers

            print("\nRESPONSE HEADERS")
            print("────────────────────────────────")

            for name, value in headers.items():
                print(f"{name}: {value}")

            print("\nSECURITY HEADERS")
            print("────────────────────────────────")

            found = 0

            for header, description in SECURITY_HEADERS.items():
                if headers.get(header):
                    print(f"[+] {description}")
                    found += 1
                else:
                    print(f"[!] {description} not detected")

            print("\n────────────────────────────────")
            print(
                f"Security headers detected: "
                f"{found}/{len(SECURITY_HEADERS)}"
            )
            print("HTTP header inspection complete.")

    except urllib.error.HTTPError as error:
        print(
            f"\n[!] HTTP error: "
            f"{error.code} {error.reason}"
        )

    except urllib.error.URLError as error:
        print(
            f"\n[!] Connection error: "
            f"{error.reason}"
        )

    except socket.timeout:
        print("\n[!] Connection timed out.")

    except TimeoutError:
        print("\n[!] Request timed out.")

    except Exception as error:
        print(f"\n[!] Unexpected error: {error}")


def detect_technologies(target):
    """Passively detect technologies from headers and HTML."""

    url = normalize_url(target)

    print("\nRECONX TECHNOLOGY DETECTOR")
    print("────────────────────────────────")
    print(f"Target: {url}")

    try:
        response, body, _ = fetch_page(target)

    except urllib.error.HTTPError as error:
        print(
            f"\n[!] HTTP error: "
            f"{error.code} {error.reason}"
        )
        return

    except urllib.error.URLError as error:
        print(
            f"\n[!] Connection error: "
            f"{error.reason}"
        )
        return

    except socket.timeout:
        print("\n[!] Connection timed out.")
        return

    except TimeoutError:
        print("\n[!] Request timed out.")
        return

    except Exception as error:
        print(f"\n[!] Unexpected error: {error}")
        return

    headers = response.headers
    body_lower = body.lower()

    detected = set()

    print(f"Status: {response.status}")

    print("\nWEB SERVER")
    print("────────────────────────────────")

    server = headers.get("Server")

    if server:
        print(f"[+] Server: {server}")

        server_lower = server.lower()

        if "cloudflare" in server_lower:
            detected.add("Cloudflare")

        if "nginx" in server_lower:
            detected.add("Nginx")

        if "apache" in server_lower:
            detected.add("Apache")

        if "iis" in server_lower:
            detected.add("Microsoft IIS")

    else:
        print("[-] Server header not exposed.")

    print("\nWEB TECHNOLOGIES")
    print("────────────────────────────────")

    content_type = headers.get(
        "Content-Type",
        "",
    )

    if "text/html" in content_type.lower():
        print("[+] HTML")
        detected.add("HTML")

    if "javascript" in content_type.lower() or re.search(
        r"<script\b",
        body,
        re.IGNORECASE,
    ):
        print("[+] JavaScript")
        detected.add("JavaScript")

    if re.search(
        r"<link[^>]+stylesheet",
        body,
        re.IGNORECASE,
    ):
        print("[+] CSS")
        detected.add("CSS")

    print("\nFRAMEWORKS")
    print("────────────────────────────────")

    frameworks = [
        (
            "Next.js",
            [
                r"_next/static",
                r"__next",
            ],
        ),
        (
            "React",
            [
                r"react",
                r"react-dom",
                r"data-reactroot",
            ],
        ),
        (
            "Vue.js",
            [
                r"vue\.js",
                r"vue@",
                r"data-v-",
            ],
        ),
        (
            "Angular",
            [
                r"ng-version",
                r"angular",
            ],
        ),
    ]

    framework_found = False

    for name, patterns in frameworks:
        if any(
            re.search(pattern, body_lower)
            for pattern in patterns
        ):
            print(f"[+] {name}")
            detected.add(name)
            framework_found = True

    if not framework_found:
        print("[-] No common frontend framework detected.")

    print("\nCMS")
    print("────────────────────────────────")

    cms_list = [
        (
            "WordPress",
            [
                r"wp-content",
                r"wp-includes",
                r"wordpress",
            ],
        ),
        (
            "Drupal",
            [
                r"drupal",
                r"sites/default",
            ],
        ),
        (
            "Joomla",
            [
                r"joomla",
                r"/media/system/js/",
            ],
        ),
    ]

    cms_found = False

    for name, patterns in cms_list:
        if any(
            re.search(pattern, body_lower)
            for pattern in patterns
        ):
            print(f"[+] {name}")
            detected.add(name)
            cms_found = True

    if not cms_found:
        print("[-] No common CMS detected.")

    print("\nCLOUD / CDN")
    print("────────────────────────────────")

    cloudflare_detected = (
        headers.get("CF-RAY")
        or headers.get("CF-Cache-Status")
        or "cloudflare" in headers.get(
            "Server",
            "",
        ).lower()
    )

    if cloudflare_detected:
        print("[+] Cloudflare")
        detected.add("Cloudflare")
    else:
        print("[-] Cloudflare not detected.")

    print("\n────────────────────────────────")
    print(
        f"Unique technologies detected: "
        f"{len(detected)}"
    )
    print("Passive technology detection complete.")


def inspect_metadata(target):
    """Inspect publicly exposed HTML metadata and links."""

    url = normalize_url(target)

    print("\nRECONX WEB METADATA INSPECTOR")
    print("────────────────────────────────")
    print(f"Target: {url}")

    try:
        response, body, page_size = fetch_page(target)

    except urllib.error.HTTPError as error:
        print(
            f"\n[!] HTTP error: "
            f"{error.code} {error.reason}"
        )
        return

    except urllib.error.URLError as error:
        print(
            f"\n[!] Connection error: "
            f"{error.reason}"
        )
        return

    except socket.timeout:
        print("\n[!] Connection timed out.")
        return

    except TimeoutError:
        print("\n[!] Request timed out.")
        return

    except Exception as error:
        print(f"\n[!] Unexpected error: {error}")
        return

    final_url = response.geturl()
    headers = response.headers

    print(f"Status      : {response.status}")
    print(f"Final URL   : {final_url}")
    print(
        f"Content-Type: "
        f"{headers.get('Content-Type', 'Unknown')}"
    )
    print(f"Page Size   : {page_size:,} bytes")

    title_match = re.search(
        r"<title[^>]*>(.*?)</title>",
        body,
        re.IGNORECASE | re.DOTALL,
    )

    title = (
        re.sub(r"\s+", " ", title_match.group(1)).strip()
        if title_match
        else None
    )

    print("\nPAGE INFORMATION")
    print("────────────────────────────────")

    if title:
        print(f"[+] Title      : {title}")
    else:
        print("[-] Title      : Not detected")

    language_match = re.search(
        r"<html[^>]+lang=[\"']([^\"']+)",
        body,
        re.IGNORECASE,
    )

    if language_match:
        print(
            f"[+] Language   : "
            f"{language_match.group(1)}"
        )
    else:
        print("[-] Language   : Not detected")

    description_match = re.search(
        r'<meta[^>]+name=["\']description["\'][^>]+'
        r'content=["\']([^"\']*)["\']',
        body,
        re.IGNORECASE,
    )

    if not description_match:
        description_match = re.search(
            r'<meta[^>]+content=["\']([^"\']*)["\'][^>]+'
            r'name=["\']description["\']',
            body,
            re.IGNORECASE,
        )

    if description_match:
        description = re.sub(
            r"\s+",
            " ",
            description_match.group(1),
        ).strip()

        print(f"[+] Description: {description}")
    else:
        print("[-] Description: Not detected")

    canonical_match = re.search(
        r'<link[^>]+rel=["\'][^"\']*canonical[^"\']*'
        r'["\'][^>]+href=["\']([^"\']+)',
        body,
        re.IGNORECASE,
    )

    if not canonical_match:
        canonical_match = re.search(
            r'<link[^>]+href=["\']([^"\']+)["\'][^>]+'
            r'rel=["\'][^"\']*canonical[^"\']*["\']',
            body,
            re.IGNORECASE,
        )

    if canonical_match:
        canonical = urllib.parse.urljoin(
            final_url,
            canonical_match.group(1),
        )
        print(f"[+] Canonical  : {canonical}")
    else:
        print("[-] Canonical  : Not detected")

    links = re.findall(
        r"<a\b[^>]*href=[\"']([^\"'#]+)",
        body,
        re.IGNORECASE,
    )

    parsed_target = urllib.parse.urlparse(final_url)
    target_hostname = parsed_target.hostname

    internal_links = set()
    external_links = set()

    for link in links:
        absolute = urllib.parse.urljoin(
            final_url,
            link,
        )

        parsed_link = urllib.parse.urlparse(absolute)

        if parsed_link.scheme not in (
            "http",
            "https",
        ):
            continue

        if parsed_link.hostname == target_hostname:
            internal_links.add(absolute)
        else:
            external_links.add(absolute)

    print("\nLINK ANALYSIS")
    print("────────────────────────────────")

    print(
        f"Total HTTP(S) links : "
        f"{len(internal_links) + len(external_links)}"
    )
    print(
        f"Internal links      : "
        f"{len(internal_links)}"
    )
    print(
        f"External links      : "
        f"{len(external_links)}"
    )

    if internal_links:
        print("\nINTERNAL LINKS")
        print("────────────────────────────────")

        for link in sorted(internal_links)[:20]:
            print(f"  {link}")

        if len(internal_links) > 20:
            print(
                f"  ... and "
                f"{len(internal_links) - 20} more"
            )

    if external_links:
        print("\nEXTERNAL LINKS")
        print("────────────────────────────────")

        for link in sorted(external_links)[:20]:
            print(f"  {link}")

        if len(external_links) > 20:
            print(
                f"  ... and "
                f"{len(external_links) - 20} more"
            )

    print("\n────────────────────────────────")
    print("Web metadata inspection complete.")
