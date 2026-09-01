# RECONX

### Intelligent Recon Assistant

RECONX is a Python-based reconnaissance toolkit designed to help security learners, developers, and authorized security testers collect useful information about systems and web applications from the command line.

> **⚠️ Authorized security testing only.**
>
> Only use RECONX against systems, networks, files, and websites that you own or have explicit permission to assess.

---

## ✨ Features

RECONX currently provides:

* 🌐 DNS reconnaissance
* 🔎 IPv4 address resolution
* 📡 Network environment information
* 🔌 Common TCP port checking
* 🛡️ HTTP security-header inspection
* 🧩 Passive web technology detection
* 📄 Web metadata inspection
* 🔗 Internal and external link discovery
* 📁 Static file analysis
* 📶 Wi-Fi capability inspection
* 📊 Consolidated reconnaissance workflow
* 📝 JSON and Markdown reporting

RECONX is designed around **read-only reconnaissance and analysis**.

---

## 📦 Requirements

### Supported systems

RECONX can run on systems with:

* Python 3.10+
* Linux
* Ubuntu
* WSL
* macOS
* Windows with Python installed

### Check Python

```bash
python3 --version
```

You should have Python 3.10 or newer.

---

# 🚀 Installation

## 1. Clone the repository

```bash
git clone https://github.com/cyberbug369/reconx.git
```

Enter the project:

```bash
cd reconx
```

---

## 2. Create a virtual environment

Linux / Ubuntu / WSL:

```bash
python3 -m venv .venv
```

Activate it:

```bash
source .venv/bin/activate
```

You should see something similar to:

```text
(.venv)
```

at the beginning of your terminal prompt.

---

## 3. Install dependencies

```bash
pip install -r requirements.txt
```

---

## 4. Verify the installation

Run:

```bash
python -m reconx.cli --help
```

You should see the available RECONX commands.

You can also check the version:

```bash
python -m reconx.cli version
```

---

# 🛠️ Usage

General format:

```bash
python -m reconx.cli COMMAND TARGET
```

---

## DNS inspection

Inspect publicly available DNS information:

```bash
python -m reconx.cli dns example.com
```

---

## HTTP headers

Inspect HTTP response headers and common security headers:

```bash
python -m reconx.cli headers example.com
```

RECONX checks for headers including:

* HSTS
* Content Security Policy
* X-Content-Type-Options
* X-Frame-Options
* Referrer-Policy
* Permissions-Policy

---

## Technology detection

Passively identify technologies exposed by a website:

```bash
python -m reconx.cli tech example.com
```

RECONX can identify technologies such as:

* HTML
* JavaScript
* CSS
* Next.js
* React
* Vue.js
* Angular
* WordPress
* Drupal
* Joomla
* Cloudflare
* Nginx
* Apache
* Microsoft IIS

---

## Web metadata

Inspect publicly exposed webpage metadata:

```bash
python -m reconx.cli metadata example.com
```

This can display:

* HTTP status
* Final URL
* Content type
* Page size
* Page title
* HTML language
* Meta description
* Canonical URL
* Internal links
* External links

---

## Common TCP ports

Check a predefined set of common TCP ports on an authorized target:

```bash
python -m reconx.cli ports example.com
```

---

## Network information

Display information about the current network environment:

```bash
python -m reconx.cli network
```

---

## Wi-Fi inspection

Inspect Wi-Fi capabilities available to the local system:

```bash
python -m reconx.cli wifi
```

---

## File analysis

Analyze a file without executing it:

```bash
python -m reconx.cli analyze example.txt
```

Save the result as JSON:

```bash
python -m reconx.cli analyze example.txt --json
```

Save the result as Markdown:

```bash
python -m reconx.cli analyze example.txt --markdown
```

---

# 🔥 Full reconnaissance workflow

RECONX can run multiple read-only reconnaissance checks together:

```bash
python -m reconx.cli recon example.com
```

The workflow currently performs:

```text
DNS inspection
      ↓
HTTP header inspection
      ↓
Technology detection
      ↓
Common TCP port check
```

You can also save the workflow output:

```bash
python -m reconx.cli recon example.com --json
```

or:

```bash
python -m reconx.cli recon example.com --markdown
```

---

# 📋 Command Reference

| Command           | Description                                  |
| ----------------- | -------------------------------------------- |
| `version`         | Show RECONX version                          |
| `network`         | Show local network information               |
| `wifi`            | Inspect Wi-Fi capabilities                   |
| `ports TARGET`    | Check common TCP ports                       |
| `dns TARGET`      | Inspect DNS information                      |
| `headers TARGET`  | Inspect HTTP security headers                |
| `tech TARGET`     | Detect web technologies                      |
| `metadata TARGET` | Inspect webpage metadata                     |
| `analyze FILE`    | Analyze a file without executing it          |
| `recon TARGET`    | Run the consolidated reconnaissance workflow |

---

# 📁 Project Structure

```text
reconx/
├── reconx/
│   ├── cli.py
│   └── modules/
│       ├── dns.py
│       ├── malware.py
│       ├── network.py
│       ├── recon.py
│       ├── report.py
│       ├── web.py
│       └── wifi.py
│
├── reports/
├── tests/
├── requirements.txt
├── README.md
└── .gitignore
```

---

# 🔐 Responsible Use

RECONX is intended for:

* Security education
* Development testing
* Lab environments
* CTF environments where permitted
* Systems you own
* Systems where you have explicit authorization to test

Do **not** use RECONX to access, scan, or analyze systems without permission.

The user is responsible for complying with all applicable laws, policies, and authorization requirements.

---

# 🧪 Development

Clone the project:

```bash
git clone https://github.com/cyberbug369/reconx.git
cd reconx
```

Create the development environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the CLI:

```bash
python -m reconx.cli --help
```

---

# 🗺️ Roadmap

Planned improvements include:

* Better DNS record enumeration
* Improved report generation
* More passive technology signatures
* Expanded metadata analysis
* Better CLI output
* Automated testing
* Configuration support
* Installable command-line entry point
* Package distribution

---

# 👨‍💻 Author

**EZEWELE aka cyberbug**

RECONX is developed as an educational security-reconnaissance project.

---

## ⭐ Support the Project

If RECONX is useful to you, consider starring the repository and following its development.

GitHub:

https://github.com/cyberbug369/reconx
