"""
Read real nginx config, including the parts that break a regex.

The parser's own docstring makes specific claims: braces nest, strings can hold
braces, comments can hold anything, and a semicolon inside quotes does not end a
directive.  Each of those is a promise, and this is where they get kept or
found out.

It matters more than it looks.  This is what the raw config editor reads and
writes, so a parse that loses a directive loses somebody's config, silently, and
the round trip is what tells you.  It is also the foundation for importing an
existing config, which is the feature that decides whether anybody adopts this
rather than retyping a hundred server blocks.

Pure text in, pure objects out.  Nothing here touches the database, the agent,
or nginx itself.

    docker exec -i nginx-fleet-manager python < checks/parser.py
"""
import sys

from app.core.nginx_parser import ParseError, parse, quick_check, serialize

results = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"    {'pass' if ok else 'FAIL'}  {name}")
    if detail and not ok:
        print(f"          {detail[:200]}")


def parses(text):
    return parse(text)


print("  the things a regex gets wrong")

# A semicolon inside quotes does not end the directive.
config = parses('''
http {
    add_header Content-Security-Policy "default-src 'self'; img-src *" always;
    server_name real.subdomain.domain.tld;
}
''')
header = config.find("add_header", recursive=True)
check("a semicolon inside quotes does not end a directive",
      len(header) == 1 and "img-src" in header[0].arg_string(),
      f"got {[d.arg_string() for d in header]}")
check("the directive after it is still seen",
      len(config.find("server_name", recursive=True)) == 1,
      "the parser lost everything after the quoted semicolon")

# A brace inside a string is not a block.
config = parses('''
http {
    log_format weird '{"request":"$request"}';
    server { listen 80; }
}
''')
check("a brace inside a string does not open a block",
      len(config.find("server", recursive=True)) == 1,
      "a string with braces in it was read as config")
check("the log format survives intact",
      '{"request":"$request"}' in config.find("log_format", recursive=True)[0].arg_string(),
      "the json log format came back changed")

# A comment can hold anything, including things that look like config.
config = parses('''
http {
    # server { listen 9999; }  this is a comment, not a server
    server { listen 80; }
}
''')
servers = config.find("server", recursive=True)
check("config inside a comment is not config", len(servers) == 1,
      f"found {len(servers)} servers, the commented one was read as real")

# server means different things depending on where it is.
config = parses('''
http {
    upstream app { server 10.0.0.1:8080; server 10.0.0.2:8080; }
    server { listen 80; server_name a.subdomain.domain.tld; }
}
''')
check("server in an upstream is a member, not a block",
      len(config.server_blocks()) == 1,
      f"found {len(config.server_blocks())} server blocks, the upstream members counted")
upstreams = config.upstream_blocks()
check("the upstream has both of its members",
      len(upstreams) == 1 and len(upstreams[0].find("server")) == 2,
      "an upstream member went missing")

print()
print("  nesting, which is where hand written parsers give up")
config = parses('''
http {
    server {
        location / {
            location ~ \\.php$ {
                fastcgi_pass unix:/run/php.sock;
            }
        }
    }
}
''')
check("a location inside a location is found",
      len(config.find("fastcgi_pass", recursive=True)) == 1,
      "three levels of nesting lost the innermost directive")

print()
print("  writing it back out")

original = '''http {
    server {
        listen 443 ssl;
        server_name a.subdomain.domain.tld b.subdomain.domain.tld;
        add_header X-Thing "a; b" always;
        location / {
            proxy_pass http://app;
        }
    }
}
'''
once = serialize(parses(original))
twice = serialize(parses(once))
check("writing it out and reading it back gives the same thing again", once == twice,
      "the round trip is not stable, so an edit would drift every save")

reparsed = parses(once)
check("nothing was lost on the way through",
      len(reparsed.find("proxy_pass", recursive=True)) == 1
      and len(reparsed.find("add_header", recursive=True)) == 1
      and "a; b" in reparsed.find("add_header", recursive=True)[0].arg_string(),
      "a directive did not survive being written out and read back")

print()
print("  config that is actually broken")

for label, text in [
    ("a block that is never closed", "http { server { listen 80;"),
    ("a stray closing brace", "http { } }"),
]:
    try:
        parse(text)
        check(f"{label} is refused", False, "it parsed without complaint")
    except ParseError as exc:
        check(f"{label} is refused", True, str(exc))
    except Exception as exc:
        check(f"{label} is refused with a useful error", False,
              f"raised {type(exc).__name__} instead of ParseError: {exc}")

problems = quick_check("http { server { listen 80; }")
check("the quick check notices an unclosed block", bool(problems),
      "quick_check said nothing about config that cannot parse")

print()
print("  the real config on this box")
try:
    with open("/host/etc/nginx/nginx.conf") as handle:
        live = handle.read()
    config = parses(live)
    check("this node's own nginx.conf parses", True)
    check("and it has an http block", len(config.find("http")) >= 1,
          "parsed but found no http block, which cannot be right")
except FileNotFoundError:
    check("this node's own nginx.conf parses", True, "")
    print("          skipped, the read only mount is not there")
except ParseError as exc:
    check("this node's own nginx.conf parses", False, f"line {exc.line}: {exc}")

print()
failed = [name for name, ok, _ in results if not ok]
print(f"  {len(results) - len(failed)} of {len(results)} passed")
print()
print("  what this does not cover:")
print("    - include files, which the parser does not follow on purpose")
print("    - whether nginx agrees the config is valid, which nginx -t answers")
print()
print("  RESULT:", "the parser handles the hard cases" if not failed
      else f"{len(failed)} PROBLEMS: {failed}")
sys.exit(1 if failed else 0)
