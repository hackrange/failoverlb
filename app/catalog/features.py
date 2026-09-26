"""
Every setting the GUI offers, described once.

To add a setting, add it here.  The form control, help popup, validation
and generated config all come from these definitions.

NGINX Plus features (active health checks, sticky sessions, slow start,
request queueing) are not offered.  PLUS_ONLY at the bottom lists them with
open source alternatives where they exist.
"""

from app.catalog.registry import Feature, HelpText, register

D = "https://nginx.org/en/docs"


# ==============================================================================
# Limits and timeouts
# ==============================================================================

register(
    Feature(
        key="client_max_body_size",
        label="Maximum upload size",
        category="limits",
        directive="client_max_body_size",
        contexts=("server", "location"),
        type="size",
        default="1m",
        placeholder="10m",
        help=HelpText(
            summary="The biggest file or form a client is allowed to send you.",
            detail=(
                "nginx stops reading and returns 413 Request Entity Too Large once a "
                "request body goes past this.  The default is only 1m, which is the "
                "single most common reason an upload that works on somebody's laptop "
                "fails as soon as it goes through a load balancer.\n\n"
                "Set it to 0 to turn the check off entirely.  Think hard before you do "
                "that.  With no limit, anybody can start a giant upload and tie up disk "
                "and memory on your box until it falls over."
            ),
            use_cases=[
                "A document site where people attach PDFs, so 1m is way too small",
                "An API taking image uploads from a phone app, where 20m is normal",
                "Locking a login form down to something tiny like 64k, since a login "
                "post should never be big and anything huge is somebody probing you",
            ],
            example="10m for a normal file upload site, 100m for video, 64k for an API that only takes JSON",
            example_config="client_max_body_size 10m;",
            docs_url=f"{D}/http/ngx_http_core_module.html#client_max_body_size",
            warning=(
                "Raising this here is only half the job.  If your backend is PHP you "
                "also have to raise upload_max_filesize and post_max_size in php.ini, "
                "and those have their own separate default that will keep failing."
            ),
        ),
    ),

    Feature(
        key="client_body_buffer_size",
        label="Request body buffer",
        category="limits",
        directive="client_body_buffer_size",
        contexts=("server", "location"),
        type="size",
        default="16k",
        advanced=True,
        help=HelpText(
            summary="How much of an upload nginx keeps in memory before writing it to disk.",
            detail=(
                "Anything bigger than this gets written to a temp file.  That works "
                "fine, it is just slower, and on a busy box all that temp file writing "
                "shows up as disk IO you did not expect.\n\n"
                "Raising it trades memory for speed.  The math is worth doing: this is "
                "per request being read, so 1m here with 500 uploads at once is 500m of "
                "memory."
            ),
            use_cases=[
                "An API taking JSON posts of a few hundred KB, so they never touch disk",
                "Cutting disk IO on a box that does a lot of small uploads",
            ],
            example="16k is fine for most sites.  128k if you take a lot of medium JSON posts.",
            example_config="client_body_buffer_size 128k;",
            docs_url=f"{D}/http/ngx_http_core_module.html#client_body_buffer_size",
        ),
    ),

    Feature(
        key="client_body_timeout",
        label="Upload timeout",
        category="limits",
        directive="client_body_timeout",
        contexts=("server", "location"),
        type="time",
        default="60s",
        help=HelpText(
            summary="How long to wait between chunks of an upload before giving up.",
            detail=(
                "This is not a total time limit for the upload.  It is how long nginx "
                "will sit there waiting for the next piece.  A slow but steady upload "
                "on a bad phone connection can run for an hour and never trip this, "
                "which is what you want.\n\n"
                "What it does stop is a client that opens a connection, says it is "
                "sending 10MB, and then sends one byte a minute to hold the connection "
                "open.  Do that a few thousand times and you have used up every worker "
                "slot nginx has.  That attack has a name, Slowloris, and this setting "
                "plus the header timeout is the fix."
            ),
            use_cases=[
                "Any site on the public internet, as basic Slowloris protection",
                "Raising it for a site people upload big files to over bad connections",
            ],
            example="60s is a good default.  Drop to 10s for an internal API where everything is on a fast network.",
            example_config="client_body_timeout 60s;",
            docs_url=f"{D}/http/ngx_http_core_module.html#client_body_timeout",
        ),
    ),

    Feature(
        key="client_header_timeout",
        label="Header timeout",
        category="limits",
        directive="client_header_timeout",
        contexts=("server",),
        type="time",
        default="60s",
        help=HelpText(
            summary="How long a client gets to finish sending its request headers.",
            detail=(
                "Same idea as the upload timeout but for the headers at the start of "
                "the request.  A client that connects and then dribbles out headers "
                "forever is holding a connection slot for free.\n\n"
                "Nothing legitimate takes long to send headers.  They are a couple of "
                "KB and they go out in one shot.  So this can be pretty tight."
            ),
            use_cases=[
                "Slowloris protection on anything facing the internet",
                "An internal service where you can safely cut it to a few seconds",
            ],
            example="15s is plenty for a public site.  5s for internal only.",
            example_config="client_header_timeout 15s;",
            docs_url=f"{D}/http/ngx_http_core_module.html#client_header_timeout",
        ),
    ),

    Feature(
        key="send_timeout",
        label="Response send timeout",
        category="limits",
        directive="send_timeout",
        contexts=("server", "location"),
        type="time",
        default="60s",
        help=HelpText(
            summary="How long to wait for the client to take the response you are sending.",
            detail=(
                "The clock only runs between writes, not for the whole response.  If a "
                "client stops reading and the send buffer fills up, this is how long "
                "nginx waits before closing the connection.\n\n"
                "Mostly it catches clients that vanished without saying goodbye, like a "
                "phone that went into a tunnel."
            ),
            use_cases=[
                "Freeing up connections held by clients that disappeared",
                "Raising it for a site serving big downloads to slow connections",
            ],
            example="60s normally.  300s if you serve large files to people on bad links.",
            example_config="send_timeout 60s;",
            docs_url=f"{D}/http/ngx_http_core_module.html#send_timeout",
        ),
    ),

    Feature(
        key="keepalive_timeout",
        label="Keep-alive timeout",
        category="limits",
        directive="keepalive_timeout",
        contexts=("server",),
        type="time",
        default="65s",
        help=HelpText(
            summary="How long an idle client connection stays open waiting for another request.",
            detail=(
                "Reusing a connection skips the TCP handshake and, on https, the whole "
                "TLS handshake.  That is a big deal.  A page pulling 40 files off your "
                "server does it over a few connections instead of 40.\n\n"
                "The cost is that idle connections still take up a slot.  Too high and "
                "a busy site runs out of workers holding connections nobody is using.  "
                "Too low and you pay for handshakes over and over."
            ),
            use_cases=[
                "A normal website with lots of images and scripts per page, where 65s helps",
                "An API where clients fire one request and leave, so a short 10s frees slots faster",
            ],
            example="65s for a website.  10s to 15s for an API.",
            example_config="keepalive_timeout 65s;",
            docs_url=f"{D}/http/ngx_http_core_module.html#keepalive_timeout",
        ),
    ),

    Feature(
        key="keepalive_requests",
        min_version=(1, 15, 3),
        label="Requests per connection",
        category="limits",
        directive="keepalive_requests",
        contexts=("server",),
        type="int",
        default=1000,
        min_value=1,
        max_value=1000000,
        advanced=True,
        help=HelpText(
            summary="How many requests one connection can serve before nginx closes it.",
            detail=(
                "Connections get recycled so their memory goes back.  On older nginx "
                "this defaulted to 100, which was low enough to hurt busy sites.  It is "
                "1000 now, which is a sane number for almost everybody."
            ),
            use_cases=["A high traffic API where you want fewer reconnects"],
            example="1000 is fine.  Push it to 10000 for an internal API doing huge request volume.",
            example_config="keepalive_requests 1000;",
            docs_url=f"{D}/http/ngx_http_core_module.html#keepalive_requests",
        ),
    ),

    Feature(
        key="large_client_header_buffers",
        label="Large header buffers",
        category="limits",
        directive="large_client_header_buffers",
        contexts=("server",),
        type="string",
        default="4 8k",
        multi_arg=True,
        advanced=True,
        placeholder="4 8k",
        help=HelpText(
            summary="Room for unusually big request headers.  Two numbers: how many buffers and how big.",
            detail=(
                "When headers do not fit, nginx returns 400 Bad Request or 494, and "
                "from the outside it looks like the site is just broken.\n\n"
                "The usual cause is a giant cookie.  Some single sign on setups put a "
                "whole signed token in one, and a long Referer on top of that will blow "
                "past the default 8k without much trouble."
            ),
            use_cases=[
                "A site behind SSO where the auth cookie is enormous",
                "Fixing random 400 errors that only hit users who have been logged in a while",
            ],
            example="4 16k gives you four buffers of 16k each",
            example_config="large_client_header_buffers 4 16k;",
            docs_url=f"{D}/http/ngx_http_core_module.html#large_client_header_buffers",
        ),
    ),
)


# ==============================================================================
# Rate limiting
# ==============================================================================

register(
    Feature(
        key="limit_req_zone_name",
        label="Rate limit zone",
        category="ratelimit",
        directive="",   # handled in the renderer, it becomes limit_req
        contexts=("server", "location"),
        type="select",
        default="",
        options=[],     # filled in from the zones you have made
        help=HelpText(
            summary="Which rate limit bucket this site or path counts against.",
            detail=(
                "Rate limits come in two pieces.  The zone says what to count and how "
                "fast is allowed, and it is shared, so several sites can draw on the "
                "same bucket.  Then you point a site or a path at it here.\n\n"
                "Almost always you count per client IP.  You make zones over on the "
                "Rate Limit Zones page."
            ),
            use_cases=[
                "Putting a strict limit on /login so nobody can brute force passwords",
                "A general limit on an API so one bad client cannot flood it",
                "Protecting an expensive search page that hits the database hard",
            ],
            example="Make a zone called login_limit at 5r/m, then point /login at it",
            example_config=(
                "# up in the http block, made for you from the zones page\n"
                "limit_req_zone $binary_remote_addr zone=login_limit:10m rate=5r/m;\n\n"
                "# down in your location\n"
                "location /login {\n"
                "    limit_req zone=login_limit burst=3 nodelay;\n"
                "}"
            ),
            docs_url=f"{D}/http/ngx_http_limit_req_module.html",
        ),
    ),

    Feature(
        key="limit_req_burst",
        label="Burst allowance",
        category="ratelimit",
        directive="",
        contexts=("server", "location"),
        type="int",
        default=0,
        min_value=0,
        max_value=10000,
        depends_on="limit_req_zone_name",
        help=HelpText(
            summary="How many extra requests can pile up in a queue before you start rejecting.",
            detail=(
                "This one trips people up, so it is worth understanding properly.\n\n"
                "nginx uses a leaky bucket.  A rate of 10r/s does not mean 10 in any "
                "given second, it means one every 100ms.  Send two back to back and "
                "without a burst the second one gets a 503 immediately, even though you "
                "are nowhere near 10 in that second.\n\n"
                "Real browsers do not politely space their requests out.  Loading one "
                "page fires off a dozen at once.  So with no burst, a totally normal "
                "page load gets rejected.  Burst is the queue that absorbs that."
            ),
            use_cases=[
                "A normal web page, where 20 covers a page pulling in lots of assets",
                "A login form, where 3 is enough for a typo or two and nothing more",
            ],
            example="Around 20 for a website, 3 to 5 for a login endpoint",
            example_config="limit_req zone=general burst=20 nodelay;",
            docs_url=f"{D}/http/ngx_http_limit_req_module.html#limit_req",
            warning=(
                "Setting a rate with no burst almost always breaks real traffic.  If "
                "people start seeing random 503s right after you turn on rate limiting, "
                "this is why."
            ),
        ),
    ),

    Feature(
        key="limit_req_nodelay",
        label="Serve burst immediately",
        category="ratelimit",
        directive="",
        contexts=("server", "location"),
        type="bool",
        default=True,
        depends_on="limit_req_zone_name",
        help=HelpText(
            summary="Serve queued burst requests right away instead of spacing them out.",
            detail=(
                "On, which is the default here, queued requests go through at once and "
                "the slots refill at your set rate.  A page load feels instant and you "
                "are still protected, because once the queue is empty the limit bites.\n\n"
                "Off, nginx holds each queued request and drips them out at the rate.  "
                "Nothing gets rejected, but users sit there waiting.  A burst of 20 at "
                "1r/s means the last person waits 20 seconds, which feels like the site "
                "is down.\n\n"
                "Leave it on unless you specifically want the slowdown."
            ),
            use_cases=[
                "On for anything a person browses, so pages load normally",
                "Off for a batch job you want throttled rather than rejected",
            ],
            example="Leave it on",
            example_config="limit_req zone=general burst=20 nodelay;",
            docs_url=f"{D}/http/ngx_http_limit_req_module.html#limit_req",
        ),
    ),

    Feature(
        key="limit_req_status",
        label="Rate limit status code",
        category="ratelimit",
        directive="limit_req_status",
        contexts=("server", "location"),
        type="int",
        default=503,
        min_value=400,
        max_value=599,
        advanced=True,
        depends_on="limit_req_zone_name",
        help=HelpText(
            summary="What status code to return when somebody hits the limit.",
            detail=(
                "The default is 503 Service Unavailable, which is a bit of a lie.  The "
                "service is fine, that particular client just asked too much.\n\n"
                "429 Too Many Requests is the honest answer and it is what clients "
                "expect.  Well behaved API clients look for 429 and back off on their "
                "own.  Give them a 503 and many of them just retry harder."
            ),
            use_cases=[
                "429 on any API, so clients back off the way they are supposed to",
                "503 if you have monitoring that specifically watches for it",
            ],
            example="429",
            example_config="limit_req_status 429;",
            docs_url=f"{D}/http/ngx_http_limit_req_module.html#limit_req_status",
        ),
    ),

    Feature(
        key="limit_conn_zone_name",
        label="Connection limit zone",
        category="ratelimit",
        directive="",
        contexts=("server", "location"),
        type="select",
        default="",
        options=[],
        help=HelpText(
            summary="Cap how many connections one client can have open at the same time.",
            detail=(
                "Different from rate limiting.  Rate limiting counts requests over "
                "time.  This counts connections open right now.\n\n"
                "It is the right tool for downloads.  Somebody pointing a download "
                "manager at your files can open 30 connections and eat all your "
                "bandwidth without breaking any request rate limit at all, because they "
                "are not making many requests, just very long ones."
            ),
            use_cases=[
                "A file download site, capping each IP to a few at a time",
                "A video streaming path where one client should not open twenty streams",
            ],
            example="10 per IP for a normal site, 2 or 3 for large downloads",
            example_config=(
                "limit_conn_zone $binary_remote_addr zone=perip:10m;\n"
                "limit_conn perip 10;"
            ),
            docs_url=f"{D}/http/ngx_http_limit_conn_module.html",
        ),
    ),

    Feature(
        key="limit_conn_count",
        label="Connections allowed",
        category="ratelimit",
        directive="",
        contexts=("server", "location"),
        type="int",
        default=10,
        min_value=1,
        max_value=10000,
        depends_on="limit_conn_zone_name",
        help=HelpText(
            summary="How many at once, per whatever the zone counts by.",
            detail=(
                "Do not go too low.  Browsers routinely open 6 connections to one host, "
                "and anything behind a shared office IP or carrier NAT will have a lot "
                "of real people coming from one address.  Set this to 2 and you will "
                "break an entire office."
            ),
            use_cases=[
                "10 to 20 for a normal site, which leaves room for shared addresses",
                "2 or 3 on a download path only",
            ],
            example="10",
            example_config="limit_conn perip 10;",
            docs_url=f"{D}/http/ngx_http_limit_conn_module.html#limit_conn",
        ),
    ),

    Feature(
        key="limit_rate",
        label="Bandwidth limit per connection",
        category="ratelimit",
        directive="limit_rate",
        contexts=("server", "location"),
        type="size",
        default="",
        placeholder="500k",
        help=HelpText(
            summary="Cap how fast one connection can download, in bytes per second.",
            detail=(
                "This is per connection, not per client.  Somebody who opens four "
                "connections gets four times this.  Pair it with a connection limit or "
                "it does not really cap anybody.\n\n"
                "Leave it blank for no limit."
            ),
            use_cases=[
                "Keeping a few big downloads from eating the whole uplink",
                "Giving anonymous users a slower speed than people who logged in",
            ],
            example="500k means about 500 KB per second per connection",
            example_config="limit_rate 500k;",
            docs_url=f"{D}/http/ngx_http_core_module.html#limit_rate",
        ),
    ),

    Feature(
        key="limit_rate_after",
        label="Full speed for the first",
        category="ratelimit",
        directive="limit_rate_after",
        contexts=("server", "location"),
        type="size",
        default="",
        placeholder="10m",
        depends_on="limit_rate",
        help=HelpText(
            summary="Send this much at full speed before the bandwidth cap kicks in.",
            detail=(
                "This is the trick that makes bandwidth limiting not feel awful.  Small "
                "files finish before the cap ever applies, so pages stay snappy.  Only "
                "the long downloads get throttled, which is the only place you cared.\n\n"
                "Without it, every image and stylesheet on the page crawls, and the site "
                "feels broken."
            ),
            use_cases=[
                "A download site where the first 10m is fast and the rest is capped",
                "Any site where you want limits without wrecking normal browsing",
            ],
            example="10m of full speed, then the limit",
            example_config="limit_rate_after 10m;\nlimit_rate 500k;",
            docs_url=f"{D}/http/ngx_http_core_module.html#limit_rate_after",
        ),
    ),
)


# ==============================================================================
# Proxy
# ==============================================================================

register(
    Feature(
        key="proxy_connect_timeout",
        label="Connect timeout",
        category="proxy",
        directive="proxy_connect_timeout",
        contexts=("server", "location"),
        type="time",
        default="5s",
        help=HelpText(
            summary="How long to wait for a backend to accept the connection.",
            detail=(
                "Just the TCP connect, not the response.  On a healthy network this "
                "takes single digit milliseconds, so a long timeout here buys you "
                "nothing except a slow failover.\n\n"
                "Keep it short.  When a backend dies, this is exactly how long every "
                "request sits there before nginx gives up and tries the next server in "
                "the pool.  Set it to 60s and one dead backend makes your whole site "
                "feel hung."
            ),
            use_cases=[
                "Backends on the same network, where 2s to 5s is plenty",
                "A backend across a WAN link, where 10s might be fair",
            ],
            example="5s.  nginx caps this at 75s no matter what you put.",
            example_config="proxy_connect_timeout 5s;",
            docs_url=f"{D}/http/ngx_http_proxy_module.html#proxy_connect_timeout",
        ),
    ),

    Feature(
        key="proxy_read_timeout",
        label="Read timeout",
        category="proxy",
        directive="proxy_read_timeout",
        contexts=("server", "location"),
        type="time",
        default="60s",
        help=HelpText(
            summary="How long to wait between pieces of the backend's response.",
            detail=(
                "The clock resets on every chunk that arrives, so this is not a cap on "
                "total response time.  A backend streaming steadily for ten minutes "
                "never trips it.  A backend that goes quiet for longer than this does.\n\n"
                "This is the setting behind most 504 Gateway Timeout errors.  If a slow "
                "report or a big export dies at exactly 60 seconds, this is why."
            ),
            use_cases=[
                "A reporting page that takes two minutes, so it needs 180s",
                "WebSockets, which need this much higher or the connection drops",
                "A normal API, where 30s is plenty and anything longer is a bug",
            ],
            example="60s normally.  3600s for WebSocket paths.",
            example_config="proxy_read_timeout 60s;",
            docs_url=f"{D}/http/ngx_http_proxy_module.html#proxy_read_timeout",
        ),
    ),

    Feature(
        key="proxy_send_timeout",
        label="Send timeout",
        category="proxy",
        directive="proxy_send_timeout",
        contexts=("server", "location"),
        type="time",
        default="60s",
        advanced=True,
        help=HelpText(
            summary="How long to wait while sending the request to the backend.",
            detail=(
                "Same reset-on-each-write behavior as the read timeout, just the other "
                "direction.  It matters when you are pushing a big upload through to a "
                "backend that is slow to take it."
            ),
            use_cases=["Large uploads going through to a slow backend"],
            example="60s",
            example_config="proxy_send_timeout 60s;",
            docs_url=f"{D}/http/ngx_http_proxy_module.html#proxy_send_timeout",
        ),
    ),

    Feature(
        key="proxy_buffering",
        label="Buffer responses",
        category="proxy",
        directive="proxy_buffering",
        contexts=("server", "location"),
        type="bool",
        default=True,
        help=HelpText(
            summary="Read the whole backend response before sending it on, instead of passing it straight through.",
            detail=(
                "On, which is the default and usually right, nginx reads from the "
                "backend as fast as it can, buffers it, and feeds it to the client at "
                "whatever speed the client can take.  That frees the backend worker "
                "immediately.  It matters a lot with slow clients, because otherwise a "
                "phone on a bad connection ties up a backend process for the whole "
                "download.\n\n"
                "Off, bytes go straight through.  You need this for anything that "
                "streams: server sent events, live logs, progress bars.  With buffering "
                "on, those sit there showing nothing and then dump everything at the "
                "end, which looks completely broken."
            ),
            use_cases=[
                "On for normal pages and APIs, which is nearly everything",
                "Off for server sent events or a streaming log viewer",
                "Off for an endpoint that streams a big generated file",
            ],
            example="On, except on streaming paths",
            example_config="proxy_buffering on;",
            docs_url=f"{D}/http/ngx_http_proxy_module.html#proxy_buffering",
        ),
    ),

    Feature(
        key="proxy_buffer_size",
        label="Header buffer size",
        category="proxy",
        directive="proxy_buffer_size",
        contexts=("server", "location"),
        type="size",
        default="4k",
        advanced=True,
        depends_on="proxy_buffering",
        help=HelpText(
            summary="Buffer for the first chunk of the backend response, which holds the headers.",
            detail=(
                "If the backend's response headers do not fit in here, nginx gives up "
                "with 502 Bad Gateway and logs 'upstream sent too big header'.\n\n"
                "Big Set-Cookie headers from an SSO system are the usual cause."
            ),
            use_cases=["Fixing 502s from a backend that sets large cookies"],
            example="4k normally, 16k behind SSO",
            example_config="proxy_buffer_size 16k;",
            docs_url=f"{D}/http/ngx_http_proxy_module.html#proxy_buffer_size",
        ),
    ),

    Feature(
        key="proxy_buffers",
        label="Response buffers",
        category="proxy",
        directive="proxy_buffers",
        contexts=("server", "location"),
        type="string",
        default="8 4k",
        multi_arg=True,
        advanced=True,
        depends_on="proxy_buffering",
        help=HelpText(
            summary="How many buffers and how big, for the body of the response.",
            detail=(
                "Two numbers, count then size.  Once these fill up, the rest of the "
                "response goes to a temp file on disk, which works but is slower.\n\n"
                "This is per request in flight.  8 4k is 32k each, so a thousand "
                "concurrent requests is 32MB.  Bumping it to 16 16k makes that 256MB, "
                "so do the math before you raise it a lot."
            ),
            use_cases=["Cutting disk writes on a site serving mostly medium sized pages"],
            example="8 4k default, 16 16k for bigger responses",
            example_config="proxy_buffers 16 16k;",
            docs_url=f"{D}/http/ngx_http_proxy_module.html#proxy_buffers",
        ),
    ),

    Feature(
        key="proxy_request_buffering",
        label="Buffer uploads",
        category="proxy",
        directive="proxy_request_buffering",
        contexts=("server", "location"),
        type="bool",
        default=True,
        advanced=True,
        help=HelpText(
            summary="Read the whole upload before starting to send it to the backend.",
            detail=(
                "On means the backend never sees a slow upload, it gets the whole thing "
                "at once off local disk or memory.\n\n"
                "Off streams it through as it arrives.  You want that for very large "
                "uploads where buffering the whole file first is wasteful, and for "
                "backends that show a real upload progress bar.  The catch is that with "
                "it off, nginx cannot retry the request on another backend if the first "
                "one dies mid upload, because the bytes are already gone."
            ),
            use_cases=[
                "Off for multi gigabyte uploads you do not want landing on disk twice",
                "Off when the backend needs to show live upload progress",
            ],
            example="Leave it on unless you have one of those reasons",
            example_config="proxy_request_buffering off;",
            docs_url=f"{D}/http/ngx_http_proxy_module.html#proxy_request_buffering",
        ),
    ),

    Feature(
        key="proxy_http_version",
        label="HTTP version to backend",
        category="proxy",
        directive="proxy_http_version",
        contexts=("server", "location"),
        type="select",
        default="1.1",
        options=[("1.0", "HTTP/1.0"), ("1.1", "HTTP/1.1 (recommended)")],
        help=HelpText(
            summary="Which HTTP version nginx speaks to your backend.",
            detail=(
                "The default is 1.0, which is a leftover from a long time ago and is "
                "almost never what you want.\n\n"
                "You need 1.1 for two things.  Keep-alive connections to the backend do "
                "not work without it, so every single request pays for a fresh TCP "
                "connection.  And WebSockets do not work at all on 1.0, since the "
                "upgrade handshake is a 1.1 thing.\n\n"
                "Set it to 1.1 and set the Connection header to empty, which this "
                "manager does for you when you pick 1.1."
            ),
            use_cases=[
                "Every proxy setup, basically",
                "Required for WebSockets",
                "Required for backend keep-alive to do anything",
            ],
            example="1.1",
            example_config="proxy_http_version 1.1;\nproxy_set_header Connection \"\";",
            docs_url=f"{D}/http/ngx_http_proxy_module.html#proxy_http_version",
        ),
    ),

    Feature(
        key="proxy_next_upstream",
        label="Retry on these conditions",
        category="proxy",
        directive="proxy_next_upstream",
        contexts=("server", "location"),
        type="multiselect",
        default=["error", "timeout"],
        options=[
            ("error", "Connection error"),
            ("timeout", "Timed out"),
            ("invalid_header", "Backend sent garbage"),
            ("http_500", "500 Internal Server Error"),
            ("http_502", "502 Bad Gateway"),
            ("http_503", "503 Service Unavailable"),
            ("http_504", "504 Gateway Timeout"),
            ("http_403", "403 Forbidden"),
            ("http_404", "404 Not Found"),
            ("non_idempotent", "Also retry POST and PATCH"),
            ("off", "Never retry"),
        ],
        help=HelpText(
            summary="When a backend fails, which failures are worth trying the next server for.",
            detail=(
                "This is what makes a pool actually highly available.  One backend dies "
                "and the request quietly goes to another one, and the user never knows.\n\n"
                "Be careful with two of these.  non_idempotent lets nginx retry POSTs, "
                "which sounds helpful and can mean an order gets placed twice.  Only "
                "turn it on if your backend can handle the same request arriving twice.\n\n"
                "http_404 is almost always wrong too.  A 404 is a real answer, not a "
                "failure, and retrying it just asks every server in the pool the same "
                "question and gets the same no."
            ),
            use_cases=[
                "error and timeout for pretty much everything",
                "Adding http_502 and http_503 when your app returns those while restarting",
            ],
            example="error, timeout, http_502, http_503",
            example_config="proxy_next_upstream error timeout http_502 http_503;",
            docs_url=f"{D}/http/ngx_http_proxy_module.html#proxy_next_upstream",
            warning=(
                "Turning on non_idempotent means a POST can run twice.  On a payment or "
                "order endpoint that is a real problem, not a theoretical one."
            ),
        ),
    ),

    Feature(
        key="proxy_next_upstream_tries",
        label="Maximum retries",
        category="proxy",
        directive="proxy_next_upstream_tries",
        contexts=("server", "location"),
        type="int",
        default=3,
        min_value=0,
        max_value=100,
        help=HelpText(
            summary="How many backends to try before giving up.  0 means try them all.",
            detail=(
                "With 0 and a big pool of dead backends, one request walks every single "
                "one, waiting for each timeout in turn.  A 20 server pool at a 5 second "
                "connect timeout is a 100 second wait before the user sees an error.\n\n"
                "Setting a real number caps that."
            ),
            use_cases=["Any pool with more than a couple of servers"],
            example="3",
            example_config="proxy_next_upstream_tries 3;",
            docs_url=f"{D}/http/ngx_http_proxy_module.html#proxy_next_upstream_tries",
        ),
    ),

    Feature(
        key="proxy_next_upstream_timeout",
        label="Total retry time",
        category="proxy",
        directive="proxy_next_upstream_timeout",
        contexts=("server", "location"),
        type="time",
        default="",
        advanced=True,
        placeholder="15s",
        help=HelpText(
            summary="Give up on retrying after this much total time, no matter how many are left.",
            detail=(
                "A backstop on top of the retry count.  Whichever limit you hit first "
                "wins.  Useful when you would rather show an error fast than keep a user "
                "waiting while you work through the pool."
            ),
            use_cases=["Anywhere a fast error beats a long wait"],
            example="15s",
            example_config="proxy_next_upstream_timeout 15s;",
            docs_url=f"{D}/http/ngx_http_proxy_module.html#proxy_next_upstream_timeout",
        ),
    ),

    Feature(
        key="proxy_ssl_verify",
        label="Verify backend certificate",
        category="proxy",
        directive="proxy_ssl_verify",
        contexts=("server", "location"),
        type="bool",
        default=False,
        advanced=True,
        help=HelpText(
            summary="Check the backend's TLS certificate when proxying over https.",
            detail=(
                "Off by default in nginx, which surprises people.  It means https to "
                "your backend is encrypted but not authenticated, so anything that can "
                "get in the middle can pretend to be your backend.\n\n"
                "Turn it on if your backends have real certs.  If they use self signed "
                "certs you also need to point nginx at that CA file, or every request "
                "fails."
            ),
            use_cases=[
                "Backends across a network you do not fully control",
                "Anywhere a compliance rule says traffic has to be authenticated end to end",
            ],
            example="On, with proxy_ssl_trusted_certificate pointing at your internal CA",
            example_config=(
                "proxy_ssl_verify on;\n"
                "proxy_ssl_verify_depth 2;\n"
                "proxy_ssl_trusted_certificate /etc/nginx/internal-ca.crt;\n"
                "proxy_ssl_name backend.internal.example.com;"
            ),
            docs_url=f"{D}/http/ngx_http_proxy_module.html#proxy_ssl_verify",
        ),
    ),

    Feature(
        key="proxy_ssl_server_name",
        label="Send SNI to backend",
        category="proxy",
        directive="proxy_ssl_server_name",
        contexts=("server", "location"),
        type="bool",
        default=True,
        advanced=True,
        help=HelpText(
            summary="Tell the backend which hostname you are asking for during the TLS handshake.",
            detail=(
                "If your backend serves more than one site on the same address, it needs "
                "SNI to know which certificate to hand back.  Without it you get the "
                "default site's cert, which will not match, and verification fails.\n\n"
                "This is the fix for the very common 'works with curl, fails through "
                "nginx' problem when proxying to an https backend."
            ),
            use_cases=[
                "Proxying to a backend that hosts several sites",
                "Proxying to anything behind a cloud load balancer",
            ],
            example="On",
            example_config="proxy_ssl_server_name on;",
            docs_url=f"{D}/http/ngx_http_proxy_module.html#proxy_ssl_server_name",
        ),
    ),

    Feature(
        key="proxy_intercept_errors",
        label="Use my error pages for backend errors",
        category="proxy",
        directive="proxy_intercept_errors",
        contexts=("server", "location"),
        type="bool",
        default=False,
        help=HelpText(
            summary="Replace backend error responses with your own error pages.",
            detail=(
                "Off, whatever the backend sends goes straight to the user, stack trace "
                "and all.  On, nginx catches anything 300 and up that you have an "
                "error_page rule for and shows yours instead.\n\n"
                "Worth turning on for anything public.  Default framework error pages "
                "leak version numbers, file paths, and sometimes bits of your code."
            ),
            use_cases=[
                "Public sites, so backend stack traces never reach a user",
                "Keeping one consistent look for errors across several different backends",
            ],
            example="On, with error pages set up for 500 and 502",
            example_config="proxy_intercept_errors on;\nerror_page 500 502 503 504 /50x.html;",
            docs_url=f"{D}/http/ngx_http_proxy_module.html#proxy_intercept_errors",
        ),
    ),

    Feature(
        key="proxy_hide_headers",
        label="Hide these response headers",
        category="proxy",
        directive="proxy_hide_header",
        contexts=("server", "location"),
        type="list",
        default=[],
        advanced=True,
        help=HelpText(
            summary="Strip headers the backend sends before the client sees them.",
            detail=(
                "Backends love to announce themselves.  X-Powered-By: PHP/8.1, "
                "X-AspNet-Version, Server: Apache/2.4.41.  None of that helps a user and "
                "all of it helps somebody scanning you pick which exploits to try.\n\n"
                "One per line."
            ),
            use_cases=[
                "Hiding backend version headers on anything public",
                "Removing internal debug headers your app adds in production",
            ],
            example="X-Powered-By, X-AspNet-Version, X-Runtime",
            example_config=(
                "proxy_hide_header X-Powered-By;\n"
                "proxy_hide_header X-AspNet-Version;"
            ),
            docs_url=f"{D}/http/ngx_http_proxy_module.html#proxy_hide_header",
        ),
    ),
)


# ==============================================================================
# Caching
# ==============================================================================

register(
    Feature(
        key="proxy_cache_zone",
        label="Cache zone",
        category="cache",
        directive="proxy_cache",
        contexts=("server", "location"),
        type="select",
        default="",
        options=[],
        help=HelpText(
            summary="Which cache to store backend responses in.  Blank turns caching off.",
            detail=(
                "Caching in front of a slow backend is usually the single biggest speed "
                "win available, and it is free.  A page that takes the backend 400ms "
                "comes back in about 1ms from cache, and the backend never sees the "
                "request at all.\n\n"
                "You make cache zones on the Cache Zones page.  The important thing to "
                "get right is what you cache: caching a logged in user's page and then "
                "handing it to somebody else is a real and very bad bug.  Use the bypass "
                "settings to keep anything with a session cookie out of the cache."
            ),
            use_cases=[
                "A content site where most pages are the same for everybody",
                "An API returning reference data that changes a few times a day",
                "Taking load off a backend that is slow and cannot easily be made faster",
            ],
            example="Point at a zone, set valid times, and bypass on session cookies",
            example_config=(
                "proxy_cache my_cache;\n"
                "proxy_cache_valid 200 301 302 10m;\n"
                "proxy_cache_valid 404 1m;\n"
                "proxy_cache_bypass $cookie_sessionid;\n"
                "proxy_no_cache $cookie_sessionid;\n"
                "add_header X-Cache-Status $upstream_cache_status always;"
            ),
            docs_url=f"{D}/http/ngx_http_proxy_module.html#proxy_cache",
            warning=(
                "Caching a page meant for one logged in user and serving it to another "
                "is a serious data leak.  Always set a bypass on your session cookie "
                "before you turn caching on for anything with logins."
            ),
        ),
    ),

    Feature(
        key="proxy_cache_valid",
        label="How long to keep responses",
        category="cache",
        directive="proxy_cache_valid",
        contexts=("server", "location"),
        type="list",
        default=["200 301 302 10m", "404 1m"],
        depends_on="proxy_cache_zone",
        help=HelpText(
            summary="How long each kind of response stays in the cache.",
            detail=(
                "Status codes first, then the time.  One rule per line.\n\n"
                "Cache your 404s too, even if only briefly.  A scanner hammering "
                "thousands of URLs that do not exist will otherwise pass every single "
                "one through to your backend."
            ),
            use_cases=[
                "10m for normal pages, 1m for 404s",
                "1h for static assets that basically never change",
            ],
            example="200 301 302 10m and then 404 1m",
            example_config="proxy_cache_valid 200 301 302 10m;\nproxy_cache_valid 404 1m;",
            docs_url=f"{D}/http/ngx_http_proxy_module.html#proxy_cache_valid",
        ),
    ),

    Feature(
        key="proxy_cache_key",
        label="Cache key",
        category="cache",
        directive="proxy_cache_key",
        contexts=("server", "location"),
        type="string",
        default="$scheme$proxy_host$request_uri",
        advanced=True,
        depends_on="proxy_cache_zone",
        help=HelpText(
            summary="What makes two requests count as the same cached thing.",
            detail=(
                "The default does not include the Host header.  So if one nginx serves "
                "www.example.com and shop.example.com off the same cache, a request for "
                "/index.html on one can be answered with the other one's page.\n\n"
                "Add $host to the key any time one cache zone is shared by more than one "
                "site."
            ),
            use_cases=[
                "Several sites sharing one cache zone, where you must add $host",
                "Caching per language by adding the Accept-Language header",
            ],
            example="$scheme$host$request_uri",
            example_config="proxy_cache_key $scheme$host$request_uri;",
            docs_url=f"{D}/http/ngx_http_proxy_module.html#proxy_cache_key",
        ),
    ),

    Feature(
        key="proxy_cache_bypass",
        label="Skip the cache when",
        category="cache",
        directive="proxy_cache_bypass",
        contexts=("server", "location"),
        type="list",
        default=["$cookie_sessionid", "$http_authorization"],
        depends_on="proxy_cache_zone",
        help=HelpText(
            summary="Go to the backend instead of the cache when any of these has a value.",
            detail=(
                "This controls reading from the cache.  There is a separate setting for "
                "writing to it, and you almost always want both, pointed at the same "
                "things.  Bypass alone means the logged in user gets a fresh page, but "
                "their personalized copy still lands in the cache for the next visitor."
            ),
            use_cases=[
                "$cookie_sessionid so logged in users always get fresh pages",
                "$http_authorization so authenticated API calls skip the cache",
            ],
            example="$cookie_sessionid and $http_authorization",
            example_config="proxy_cache_bypass $cookie_sessionid $http_authorization;",
            docs_url=f"{D}/http/ngx_http_proxy_module.html#proxy_cache_bypass",
        ),
    ),

    Feature(
        key="proxy_no_cache",
        label="Never store when",
        category="cache",
        directive="proxy_no_cache",
        contexts=("server", "location"),
        type="list",
        default=["$cookie_sessionid", "$http_authorization"],
        depends_on="proxy_cache_zone",
        help=HelpText(
            summary="Do not save the response to cache when any of these has a value.",
            detail=(
                "The other half of bypass.  This is the one that actually stops one "
                "user's private page from being handed to somebody else later.  Set it "
                "to the same list as your bypass rule."
            ),
            use_cases=["Always, on any site that has logins"],
            example="Same list as the bypass setting",
            example_config="proxy_no_cache $cookie_sessionid $http_authorization;",
            docs_url=f"{D}/http/ngx_http_proxy_module.html#proxy_no_cache",
        ),
    ),

    Feature(
        key="proxy_cache_use_stale",
        label="Serve stale cache when the backend is down",
        category="cache",
        directive="proxy_cache_use_stale",
        contexts=("server", "location"),
        type="multiselect",
        default=["error", "timeout", "updating"],
        options=[
            ("error", "Backend errored"),
            ("timeout", "Backend timed out"),
            ("updating", "While refreshing the entry"),
            ("http_500", "Backend returned 500"),
            ("http_502", "Backend returned 502"),
            ("http_503", "Backend returned 503"),
            ("http_504", "Backend returned 504"),
            ("http_403", "Backend returned 403"),
            ("http_429", "Backend returned 429"),
        ],
        depends_on="proxy_cache_zone",
        help=HelpText(
            summary="Serve an expired cached copy rather than an error when the backend is broken.",
            detail=(
                "This is the closest thing to a free superpower in nginx.  Your whole "
                "backend goes down and visitors keep seeing a slightly old version of "
                "the site instead of a 502.  For a content site that can turn a total "
                "outage into something almost nobody notices.\n\n"
                "The updating option is worth having on by itself.  Without it, when a "
                "popular page expires, every request that arrives at that moment goes to "
                "the backend at once.  With it, one request refreshes while everybody "
                "else is served the slightly stale copy."
            ),
            use_cases=[
                "Any content site, so a backend outage does not become a site outage",
                "Stopping a stampede on popular pages when the cache entry expires",
            ],
            example="error, timeout, updating, http_502, http_503",
            example_config=(
                "proxy_cache_use_stale error timeout updating http_502 http_503;\n"
                "proxy_cache_background_update on;\n"
                "proxy_cache_lock on;"
            ),
            docs_url=f"{D}/http/ngx_http_proxy_module.html#proxy_cache_use_stale",
        ),
    ),

    Feature(
        key="proxy_cache_background_update",
        min_version=(1, 11, 10),
        label="Refresh stale entries in the background",
        category="cache",
        directive="proxy_cache_background_update",
        contexts=("server", "location"),
        type="bool",
        default=True,
        depends_on="proxy_cache_zone",
        help=HelpText(
            summary="Hand back the stale copy right away and refresh it behind the scenes.",
            detail=(
                "Without this, whoever unluckily arrives right when an entry expires has "
                "to wait for the backend.  With it, they get the old copy instantly and "
                "nginx quietly fetches a fresh one for the next person.\n\n"
                "Needs 'updating' checked in the stale settings to do anything."
            ),
            use_cases=["Any cached site where you want consistently fast page loads"],
            example="On",
            example_config="proxy_cache_background_update on;",
            docs_url=f"{D}/http/ngx_http_proxy_module.html#proxy_cache_background_update",
        ),
    ),

    Feature(
        key="proxy_cache_lock",
        label="Only let one request refresh a page",
        category="cache",
        directive="proxy_cache_lock",
        contexts=("server", "location"),
        type="bool",
        default=True,
        depends_on="proxy_cache_zone",
        help=HelpText(
            summary="When a page is not cached, let one request fetch it while the rest wait.",
            detail=(
                "This is the fix for a cache stampede.  A popular page expires, a "
                "thousand requests all miss at once, and all thousand hit the backend "
                "for the same thing.  Backends fall over from exactly this.\n\n"
                "With the lock on, one goes through and the others wait for it, then all "
                "get served from the freshly cached copy."
            ),
            use_cases=["Any high traffic cached site"],
            example="On",
            example_config="proxy_cache_lock on;\nproxy_cache_lock_timeout 5s;",
            docs_url=f"{D}/http/ngx_http_proxy_module.html#proxy_cache_lock",
        ),
    ),

    Feature(
        key="proxy_cache_min_uses",
        label="Cache after this many requests",
        category="cache",
        directive="proxy_cache_min_uses",
        contexts=("server", "location"),
        type="int",
        default=1,
        min_value=1,
        max_value=1000,
        advanced=True,
        depends_on="proxy_cache_zone",
        help=HelpText(
            summary="Only start caching something once it has been asked for this many times.",
            detail=(
                "Keeps one-hit URLs out of the cache.  On a big site with a very long "
                "tail of rarely visited pages, caching every single one wastes the disk "
                "on things nobody will ask for again."
            ),
            use_cases=["A large site where only some pages are actually popular"],
            example="1 caches everything.  3 only caches things asked for repeatedly.",
            example_config="proxy_cache_min_uses 3;",
            docs_url=f"{D}/http/ngx_http_proxy_module.html#proxy_cache_min_uses",
        ),
    ),

    Feature(
        key="cache_status_header",
        label="Add an X-Cache-Status header",
        category="cache",
        directive="",
        contexts=("server", "location"),
        type="bool",
        default=True,
        depends_on="proxy_cache_zone",
        help=HelpText(
            summary="Tell you whether each response came from cache.",
            detail=(
                "Adds a header saying HIT, MISS, BYPASS, EXPIRED, STALE, UPDATING or "
                "REVALIDATED.  When somebody says caching is not working, this is how "
                "you find out in about five seconds instead of guessing.\n\n"
                "Some people take it off in production because it tells the outside "
                "world a little about your setup.  It is pretty harmless and being able "
                "to debug is worth more."
            ),
            use_cases=["Checking your caching actually works", "Debugging why a page is stale"],
            example="curl -I https://www.example.com/ and look for X-Cache-Status",
            example_config="add_header X-Cache-Status $upstream_cache_status always;",
            docs_url=f"{D}/http/ngx_http_upstream_module.html#var_upstream_cache_status",
        ),
    ),

    Feature(
        key="cache_purge_enabled",
        label="Allow cache purging",
        category="cache",
        directive="",
        contexts=("server", "location"),
        type="bool",
        default=False,
        module="ngx_cache_purge",
        advanced=True,
        depends_on="proxy_cache_zone",
        help=HelpText(
            summary="Let the management network clear cached pages on demand.",
            detail=(
                "Adds a PURGE method that drops a cached entry so the next request "
                "fetches it fresh.  Handy right after a deploy or a content change, when "
                "waiting for the cache to expire on its own is not good enough.\n\n"
                "This is locked to the management allow list.  A purge endpoint anybody "
                "can reach is a way to force every request through to your backend, "
                "which is a denial of service with extra steps."
            ),
            use_cases=[
                "Clearing a page right after publishing a change",
                "A deploy script that purges the pages it touched",
            ],
            example="curl -X PURGE https://www.example.com/some/page from a management host",
            example_config=(
                "location ~ /purge(/.*) {\n"
                "    allow 10.20.30.0/24;\n"
                "    deny all;\n"
                "    proxy_cache_purge my_cache $scheme$host$1;\n"
                "}"
            ),
            docs_url="https://github.com/nginx-modules/ngx_cache_purge",
        ),
    ),
)


# ==============================================================================
# Compression
# ==============================================================================

register(
    Feature(
        key="gzip",
        label="Enable gzip",
        category="compression",
        directive="gzip",
        contexts=("server", "location"),
        type="bool",
        default=True,
        help=HelpText(
            summary="Compress text responses on the way out.",
            detail=(
                "Text compresses really well.  HTML, CSS, JavaScript and JSON typically "
                "come down by 70 to 80 percent, which is a big deal for anybody on a "
                "phone.\n\n"
                "Do not bother with images, video, or zip files.  They are already "
                "compressed, so you burn CPU and the file comes out about the same size "
                "or slightly bigger."
            ),
            use_cases=["Basically every website", "APIs returning JSON, which compresses very well"],
            example="On, with a sensible type list and level 5",
            example_config=(
                "gzip on;\n"
                "gzip_vary on;\n"
                "gzip_min_length 1024;\n"
                "gzip_comp_level 5;\n"
                "gzip_types text/plain text/css application/json application/javascript text/xml;"
            ),
            docs_url=f"{D}/http/ngx_http_gzip_module.html",
        ),
    ),

    Feature(
        key="gzip_comp_level",
        label="Compression level",
        category="compression",
        directive="gzip_comp_level",
        contexts=("server", "location"),
        type="int",
        default=5,
        min_value=1,
        max_value=9,
        depends_on="gzip",
        help=HelpText(
            summary="How hard to compress, 1 through 9.",
            detail=(
                "The returns fall off a cliff.  Going from 1 to 5 saves a lot of bytes "
                "for a little CPU.  Going from 5 to 9 costs several times the CPU and "
                "saves a couple more percent.\n\n"
                "5 or 6 is the sweet spot and there is not much reason to go past it."
            ),
            use_cases=["5 for almost everything", "1 or 2 if your CPU is the bottleneck"],
            example="5",
            example_config="gzip_comp_level 5;",
            docs_url=f"{D}/http/ngx_http_gzip_module.html#gzip_comp_level",
        ),
    ),

    Feature(
        key="gzip_min_length",
        label="Only compress files bigger than",
        category="compression",
        directive="gzip_min_length",
        contexts=("server", "location"),
        type="size",
        default="1024",
        depends_on="gzip",
        help=HelpText(
            summary="Skip compression for responses smaller than this.",
            detail=(
                "Tiny responses do not compress usefully.  Below about 1KB the gzip "
                "header overhead can make the result bigger than what you started with, "
                "and you spent CPU to get there."
            ),
            use_cases=["Leave it around 1024 for most sites"],
            example="1024",
            example_config="gzip_min_length 1024;",
            docs_url=f"{D}/http/ngx_http_gzip_module.html#gzip_min_length",
        ),
    ),

    Feature(
        key="gzip_types",
        label="Compress these content types",
        category="compression",
        directive="gzip_types",
        contexts=("server", "location"),
        type="list",
        default=[
            "text/plain", "text/css", "text/xml", "text/javascript",
            "application/json", "application/javascript", "application/xml",
            "application/xml+rss", "application/vnd.api+json",
            "image/svg+xml", "application/wasm",
        ],
        depends_on="gzip",
        help=HelpText(
            summary="Which content types get compressed.  text/html is always included.",
            detail=(
                "nginx always compresses text/html and you cannot list it, it is just "
                "there.  Everything else you want has to be listed.\n\n"
                "The one people forget is image/svg+xml.  SVGs are text and compress "
                "beautifully, but the name says image so they get skipped."
            ),
            use_cases=["The default list covers a normal website and API"],
            example="text/css, application/json, application/javascript, image/svg+xml",
            example_config="gzip_types text/css application/json application/javascript image/svg+xml;",
            docs_url=f"{D}/http/ngx_http_gzip_module.html#gzip_types",
        ),
    ),

    Feature(
        key="gzip_vary",
        label="Add Vary: Accept-Encoding",
        category="compression",
        directive="gzip_vary",
        contexts=("server", "location"),
        type="bool",
        default=True,
        depends_on="gzip",
        help=HelpText(
            summary="Tell caches that the response differs depending on whether the client takes gzip.",
            detail=(
                "Without this header, a cache in the middle can store the compressed "
                "version and then hand it to a client that never said it could handle "
                "gzip.  That client gets binary garbage.\n\n"
                "Rare these days since everything supports gzip, but it costs nothing to "
                "be correct."
            ),
            use_cases=["Any site behind a CDN or another caching proxy"],
            example="On",
            example_config="gzip_vary on;",
            docs_url=f"{D}/http/ngx_http_gzip_module.html#gzip_vary",
        ),
    ),

    Feature(
        key="gzip_proxied",
        label="Compress proxied responses",
        category="compression",
        directive="gzip_proxied",
        contexts=("server", "location"),
        type="select",
        default="any",
        options=[
            ("off", "Never compress proxied responses"),
            ("any", "Always compress them"),
            ("expired", "Only if the response is expired"),
            ("no-cache", "Only when Cache-Control says no-cache"),
            ("no-store", "Only when Cache-Control says no-store"),
            ("private", "Only when Cache-Control says private"),
        ],
        advanced=True,
        depends_on="gzip",
        help=HelpText(
            summary="Whether to compress responses that came from a backend.",
            detail=(
                "The default is off, which catches people out.  If your site is a proxy "
                "in front of an app, turning gzip on does nothing at all until you also "
                "set this.  Everything you serve came from a backend, so it all gets "
                "skipped."
            ),
            use_cases=["Set it to any on any proxy site, which is most of them"],
            example="any",
            example_config="gzip_proxied any;",
            docs_url=f"{D}/http/ngx_http_gzip_module.html#gzip_proxied",
        ),
    ),

    Feature(
        key="gzip_static",
        label="Serve pre-compressed .gz files",
        category="compression",
        directive="gzip_static",
        contexts=("server", "location"),
        type="bool",
        default=False,
        module="http_gzip_static_module",
        advanced=True,
        help=HelpText(
            summary="Look for a file.gz next to each file and serve that instead of compressing every time.",
            detail=(
                "Your build already produces app.js.  If it also produces app.js.gz, "
                "nginx can just send that and skip compressing the same file over and "
                "over for every visitor.\n\n"
                "You can compress harder offline than you ever would at request time, so "
                "the files come out smaller too.  Nothing to lose here if your build can "
                "produce the files."
            ),
            use_cases=["A site with built frontend assets", "Any static file heavy site"],
            example="Run gzip -9 -k over your assets at build time",
            example_config="gzip_static on;",
            docs_url=f"{D}/http/ngx_http_gzip_static_module.html",
        ),
    ),
)


# ==============================================================================
# Security headers
# ==============================================================================

register(
    Feature(
        key="hsts_enabled",
        label="HSTS (force https)",
        category="security",
        directive="",
        contexts=("server",),
        type="bool",
        default=True,
        help=HelpText(
            summary="Tell browsers to only ever use https for this site, for a long time.",
            detail=(
                "Once a browser sees this header it refuses to speak plain http to your "
                "domain at all, even if somebody types http:// or clicks an old link.  "
                "It stops the attack where somebody on the same wifi quietly downgrades "
                "your connection before the redirect happens.\n\n"
                "Take the warning seriously.  Browsers remember this and there is no way "
                "to call it back.  If your cert expires and you cannot fix it fast, "
                "visitors cannot reach the site at all, and you cannot tell them to just "
                "use http for now."
            ),
            use_cases=["Any site that should always be https, which is all of them now"],
            example="Start at max-age=300 while testing, then raise it to a year",
            example_config='add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
            docs_url="https://developer.mozilla.org/docs/Web/HTTP/Headers/Strict-Transport-Security",
            warning=(
                "Do not turn on includeSubDomains until you are certain every single "
                "subdomain has a working cert.  It covers ones you forgot about, and "
                "internal-only hostnames under the same domain are the usual casualty."
            ),
        ),
    ),

    Feature(
        key="hsts_max_age",
        label="HSTS duration",
        category="security",
        directive="",
        contexts=("server",),
        type="int",
        default=31536000,
        min_value=0,
        max_value=63072000,
        unit="seconds",
        depends_on="hsts_enabled",
        help=HelpText(
            summary="How long browsers should remember to force https.",
            detail=(
                "31536000 is one year and it is the normal answer.  Start much lower, "
                "like 300, while you are testing.  That way a mistake ages out in five "
                "minutes instead of hanging around for a year."
            ),
            use_cases=["300 while testing", "31536000 once you are confident"],
            example="31536000",
            example_config='add_header Strict-Transport-Security "max-age=31536000" always;',
        ),
    ),

    Feature(
        key="hsts_include_subdomains",
        label="Apply HSTS to all subdomains",
        category="security",
        directive="",
        contexts=("server",),
        type="bool",
        default=False,
        depends_on="hsts_enabled",
        help=HelpText(
            summary="Extend the https-only rule to every subdomain under this one.",
            detail=(
                "Covers subdomains you have not even thought about.  That is the point, "
                "and it is also the danger.  An internal tool at "
                "oldbox.internal.example.com with a self signed cert becomes unreachable "
                "from any browser that has seen this header on example.com."
            ),
            use_cases=["Once every subdomain definitely has a valid cert"],
            example="Off until you have checked every subdomain",
            example_config='add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
            warning="Check every subdomain first.  This is not easy to undo.",
        ),
    ),

    Feature(
        key="x_frame_options",
        label="Frame embedding policy",
        category="security",
        directive="",
        contexts=("server", "location"),
        type="select",
        default="SAMEORIGIN",
        options=[
            ("", "Do not send the header"),
            ("DENY", "Nobody can frame this site"),
            ("SAMEORIGIN", "Only this site can frame itself"),
        ],
        help=HelpText(
            summary="Controls whether other sites can put your pages inside an iframe.",
            detail=(
                "Stops clickjacking.  The attack is simple: somebody loads your real "
                "site in an invisible iframe on their page, lines up an invisible button "
                "over something tempting, and the user clicks your Delete Account button "
                "thinking they clicked something else.\n\n"
                "SAMEORIGIN is right for nearly everybody.  DENY if your pages are never "
                "framed even by yourself."
            ),
            use_cases=[
                "SAMEORIGIN for a normal site",
                "DENY for an admin panel or anything with sensitive actions",
            ],
            example="SAMEORIGIN",
            example_config='add_header X-Frame-Options "SAMEORIGIN" always;',
            docs_url="https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Frame-Options",
        ),
    ),

    Feature(
        key="x_content_type_options",
        label="Stop content type sniffing",
        category="security",
        directive="",
        contexts=("server", "location"),
        type="bool",
        default=True,
        help=HelpText(
            summary="Make browsers trust the content type you sent instead of guessing.",
            detail=(
                "Browsers used to peek at file contents and decide for themselves what "
                "something was.  That means a file you serve as plain text, because a "
                "user uploaded it, can get run as JavaScript if it happens to look like "
                "code.\n\n"
                "This header turns that guessing off.  One line, no downside, turn it on."
            ),
            use_cases=["Every site", "Especially anywhere users can upload files"],
            example="On",
            example_config='add_header X-Content-Type-Options "nosniff" always;',
            docs_url="https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Content-Type-Options",
        ),
    ),

    Feature(
        key="referrer_policy",
        label="Referrer policy",
        category="security",
        directive="",
        contexts=("server", "location"),
        type="select",
        default="strict-origin-when-cross-origin",
        options=[
            ("", "Do not send the header"),
            ("no-referrer", "Never send a referrer"),
            ("same-origin", "Only send it to this same site"),
            ("strict-origin", "Send only the domain, and only over https"),
            ("strict-origin-when-cross-origin", "Full URL on this site, domain only elsewhere"),
            ("no-referrer-when-downgrade", "Anything except https to http"),
        ],
        help=HelpText(
            summary="How much of the current URL to hand to sites your users click through to.",
            detail=(
                "By default a browser tells the next site the full URL the user came "
                "from.  That leaks more than people expect.  A URL like "
                "/reset-password?token=abc123 gets handed to every third party resource "
                "on the page.\n\n"
                "The default here sends the full URL within your own site, where it is "
                "useful for analytics, and only the bare domain to anybody else."
            ),
            use_cases=[
                "strict-origin-when-cross-origin for a normal site",
                "no-referrer for anything where the URLs themselves are sensitive",
            ],
            example="strict-origin-when-cross-origin",
            example_config='add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
            docs_url="https://developer.mozilla.org/docs/Web/HTTP/Headers/Referrer-Policy",
        ),
    ),

    Feature(
        key="content_security_policy",
        label="Content Security Policy",
        header_value=True,
        category="security",
        directive="",
        contexts=("server", "location"),
        type="text",
        default="",
        placeholder="default-src 'self'; img-src 'self' data:; frame-ancestors 'self'",
        advanced=True,
        help=HelpText(
            summary="A list of where the browser is allowed to load things from.",
            detail=(
                "The strongest defense against cross site scripting there is.  Even if "
                "somebody manages to inject a script tag into your page, the browser "
                "refuses to run it because it did not come from a source you listed.\n\n"
                "It is also the easiest one to get wrong and break your own site with.  "
                "Use the report-only header first.  It logs what would have been blocked "
                "without actually blocking anything, so you can find every problem before "
                "any user does."
            ),
            use_cases=[
                "Locking down a site that handles anything sensitive",
                "Meeting a security requirement that asks for CSP",
            ],
            example="default-src 'self'; img-src 'self' data: https:; frame-ancestors 'self'",
            example_config=(
                "# test first with this, it only reports\n"
                "add_header Content-Security-Policy-Report-Only \"default-src 'self'\" always;\n\n"
                "# then switch to the real one\n"
                "add_header Content-Security-Policy \"default-src 'self'\" always;"
            ),
            docs_url="https://developer.mozilla.org/docs/Web/HTTP/Headers/Content-Security-Policy",
            warning=(
                "A CSP that is too strict will silently break your own JavaScript and "
                "styles.  Always run it in report-only mode for a while first."
            ),
        ),
    ),

    Feature(
        key="csp_report_only",
        label="CSP in report-only mode",
        category="security",
        directive="",
        contexts=("server", "location"),
        type="bool",
        default=False,
        advanced=True,
        depends_on="content_security_policy",
        help=HelpText(
            summary="Log what the policy would block, without actually blocking it.",
            detail=(
                "Always start here.  Leave it on for a week, watch the browser console "
                "and any reports, fix what shows up, then turn it off so the policy "
                "starts enforcing."
            ),
            use_cases=["Rolling out a CSP without breaking the site"],
            example="On for the first week or two",
            example_config='add_header Content-Security-Policy-Report-Only "default-src \'self\'" always;',
        ),
    ),

    Feature(
        key="permissions_policy",
        label="Permissions policy",
        header_value=True,
        category="security",
        directive="",
        contexts=("server", "location"),
        type="string",
        default="",
        placeholder="geolocation=(), microphone=(), camera=()",
        advanced=True,
        help=HelpText(
            summary="Turn off browser features your site does not use.",
            detail=(
                "Cuts down what an injected script could do.  If your site never needs "
                "the camera, saying so means nothing on the page can ask for it, "
                "including something that got injected.\n\n"
                "An empty pair of parens means nobody, including you."
            ),
            use_cases=["Any site that does not need camera, mic or location"],
            example="geolocation=(), microphone=(), camera=(), payment=()",
            example_config='add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;',
            docs_url="https://developer.mozilla.org/docs/Web/HTTP/Headers/Permissions-Policy",
        ),
    ),

    Feature(
        key="server_header_mode",
        label="Server header",
        category="security",
        directive="more_clear_headers",
        contexts=("server",),
        type="select",
        default="suppress",
        module="headers_more",
        options=[
            ("suppress", "Remove it completely (recommended)"),
            ("custom", "Replace it with something of your own"),
            ("default", "Leave nginx's own header alone"),
        ],
        help=HelpText(
            summary="What goes in the Server header, or whether to send one at all.",
            detail=(
                "Turning off server_tokens only hides the version number.  nginx still "
                "sends 'Server: nginx', which tells anybody scanning exactly what you "
                "are running, just not which release.\n\n"
                "Removing the header entirely needs the headers-more module, which the "
                "installer compiles in.  Then a banner grab gets nothing at all.\n\n"
                "Be realistic about what this buys you.  Anybody determined can "
                "fingerprint a web server from how it behaves, and hiding the name will "
                "not stop them.  What it does stop is the far more common case: a script "
                "scanning the whole internet for one vulnerable version, reading the "
                "header, and adding you to a list.  Not being on that list is worth the "
                "one line."
            ),
            use_cases=[
                "Anything facing the internet, where the default is to remove it",
                "Replacing it with a node name like lb-01, which is genuinely useful "
                "when you are chasing which box served a bad response",
                "Leaving it alone only when something downstream insists on reading it",
            ],
            example="Remove it completely, unless you have a reason not to",
            example_config=(
                "# gone entirely\n"
                "more_clear_headers Server;\n\n"
                "# or replaced with something of your own\n"
                'more_set_headers "Server: lb-01";'
            ),
            docs_url="https://github.com/openresty/headers-more-nginx-module",
        ),
    ),

    Feature(
        key="server_header_value",
        label="Custom Server header",
        category="security",
        directive="more_set_headers",
        contexts=("server",),
        type="string",
        default="",
        module="headers_more",
        placeholder="lb-01",
        depends_on="server_header_mode",
        help=HelpText(
            summary="What to put in the Server header when you are replacing it.",
            detail=(
                "Anything you like.  A node name is the useful choice, because then a "
                "response tells you which box produced it without needing to add a "
                "header of your own.\n\n"
                "Avoid anything that names real software and a version.  Putting "
                "'Apache/2.4.1' in there to be clever mostly means somebody wastes an "
                "afternoon, including possibly you in six months."
            ),
            use_cases=[
                "lb-01 or lb-02, so you can tell which node answered",
                "A single flat name across the fleet if you would rather not say",
            ],
            example="lb-01",
            example_config='more_set_headers "Server: lb-01";',
        ),
    ),

    Feature(
        key="server_tokens",
        label="Show nginx version",
        category="security",
        directive="server_tokens",
        contexts=("server",),
        type="bool",
        default=False,
        help=HelpText(
            summary="Whether error pages and the Server header show your exact nginx version.",
            detail=(
                "Off means the version number goes away.  It does not stop anybody "
                "determined, but it does keep you out of the results when somebody scans "
                "the internet for one specific vulnerable version.\n\n"
                "The installer already goes further than this and replaces the whole "
                "Server header using the headers-more module, so it just says 'server'."
            ),
            use_cases=["Every public site"],
            example="Off",
            example_config="server_tokens off;",
            docs_url=f"{D}/http/ngx_http_core_module.html#server_tokens",
        ),
    ),

    Feature(
        key="custom_response_headers",
        label="Custom response headers",
        header_value=True,
        category="headers",
        directive="",
        contexts=("server", "location"),
        type="list",
        default=[],
        help=HelpText(
            summary="Extra headers to add to every response.  One per line, name then value.",
            detail=(
                "One gotcha worth knowing about add_header.  If you add a header in a "
                "location block, every add_header you set higher up in the server block "
                "stops applying to that location.  It is not additive, it replaces.\n\n"
                "This manager works around it by writing the full set into each block, "
                "so you do not have to think about it."
            ),
            use_cases=[
                "A build or version header so you know which release answered",
                "Cache-Control rules for a specific path",
            ],
            example="X-App-Version 2.4.1",
            example_config='add_header X-App-Version "2.4.1" always;',
            docs_url=f"{D}/http/ngx_http_headers_module.html#add_header",
        ),
    ),

    Feature(
        key="block_dotfiles",
        label="Block hidden files",
        category="security",
        directive="",
        contexts=("server",),
        type="bool",
        default=True,
        help=HelpText(
            summary="Refuse any request for a path starting with a dot.",
            detail=(
                "Stops .git, .env, .htaccess and friends from being downloadable.  This "
                "is not a theoretical problem.  Scanners hit /.env and /.git/config on "
                "every site on the internet constantly, because it works often enough to "
                "be worth doing, and a leaked .env usually has database passwords in it."
            ),
            use_cases=["Every site serving files off disk", "Any deploy that copies a whole repo"],
            example="On",
            example_config=(
                "location ~ /\\. {\n"
                "    deny all;\n"
                "    access_log off;\n"
                "    log_not_found off;\n"
                "}"
            ),
        ),
    ),

    Feature(
        key="block_common_exploits",
        label="Block common exploit patterns",
        category="security",
        directive="",
        contexts=("server",),
        type="bool",
        default=False,
        advanced=True,
        help=HelpText(
            summary="Reject requests with obvious attack patterns in the URL.",
            detail=(
                "Catches the noisy stuff: directory traversal with ../, SQL keywords "
                "jammed into query strings, script tags in parameters.\n\n"
                "Be realistic about what this is.  It is a speed bump, not a web "
                "application firewall.  It will stop a dumb scanner and it will not stop "
                "anybody who is actually trying.  It can also block real requests if "
                "your app legitimately puts odd looking things in a query string, so "
                "watch your logs after turning it on."
            ),
            use_cases=["Cutting down scanner noise in the logs"],
            example="Off unless you have checked it does not break your app",
            example_config=(
                "if ($request_uri ~* \"(\\.\\./|<script|union.*select)\") {\n"
                "    return 403;\n"
                "}"
            ),
            warning=(
                "This is not a WAF.  Do not let it convince anybody the app does not "
                "need to validate its own input."
            ),
        ),
    ),
)


# ==============================================================================
# CORS
# ==============================================================================

register(
    Feature(
        key="cors_enabled",
        label="Enable CORS",
        category="headers",
        directive="",
        contexts=("server",),
        type="bool",
        default=False,
        help=HelpText(
            summary="Let JavaScript on other sites call this one.",
            detail=(
                "Browsers block cross site requests by default.  If a page on "
                "app.example.com needs to call api.example.com, the API has to say that "
                "is allowed, and this is how.\n\n"
                "Turning this on also handles the OPTIONS preflight request browsers "
                "send first, which is the piece people forget and then spend an "
                "afternoon on."
            ),
            use_cases=[
                "An API at api.example.com called by a frontend at app.example.com",
                "A public API meant to be called from anywhere",
            ],
            example="Allow https://app.example.com specifically, not *",
            example_config=(
                "add_header Access-Control-Allow-Origin \"https://app.example.com\" always;\n"
                "add_header Access-Control-Allow-Methods \"GET, POST, OPTIONS\" always;\n"
                "add_header Access-Control-Allow-Headers \"Authorization, Content-Type\" always;\n\n"
                "if ($request_method = OPTIONS) {\n"
                "    return 204;\n"
                "}"
            ),
            docs_url="https://developer.mozilla.org/docs/Web/HTTP/CORS",
        ),
    ),

    Feature(
        key="cors_allow_origin",
        label="Allowed origins",
        category="headers",
        directive="",
        contexts=("server",),
        type="list",
        default=["*"],
        depends_on="cors_enabled",
        help=HelpText(
            summary="Which sites are allowed to call this one.  One per line.",
            detail=(
                "Use * only for a genuinely public API with no authentication.  For "
                "anything behind a login, list the real origins.\n\n"
                "You cannot combine * with credentials.  Browsers refuse that "
                "combination on purpose, because it would let any website on the "
                "internet make authenticated calls as your logged in user."
            ),
            use_cases=[
                "https://app.example.com for your own frontend",
                "* for a public read only API",
            ],
            example="https://app.example.com",
            example_config='add_header Access-Control-Allow-Origin "https://app.example.com" always;',
            warning=(
                "Setting * together with credentials is the classic CORS mistake.  "
                "Browsers will reject it, and if you work around the rejection you have "
                "opened your API to every site on the internet."
            ),
        ),
    ),

    Feature(
        key="cors_allow_methods",
        label="Allowed methods",
        category="headers",
        directive="",
        contexts=("server",),
        type="multiselect",
        default=["GET", "POST", "OPTIONS"],
        options=[
            ("GET", "GET"), ("POST", "POST"), ("PUT", "PUT"),
            ("PATCH", "PATCH"), ("DELETE", "DELETE"),
            ("OPTIONS", "OPTIONS"), ("HEAD", "HEAD"),
        ],
        depends_on="cors_enabled",
        help=HelpText(
            summary="Which HTTP methods cross site callers may use.",
            detail="Keep OPTIONS in the list or preflight fails and nothing works.",
            use_cases=["GET and OPTIONS for a read only API", "Add POST, PUT and DELETE for a full one"],
            example="GET, POST, OPTIONS",
            example_config='add_header Access-Control-Allow-Methods "GET, POST, OPTIONS" always;',
        ),
    ),

    Feature(
        key="cors_allow_headers",
        label="Allowed request headers",
        category="headers",
        directive="",
        contexts=("server",),
        type="list",
        default=["Authorization", "Content-Type"],
        depends_on="cors_enabled",
        help=HelpText(
            summary="Which headers a cross site caller is allowed to send.",
            detail=(
                "Anything beyond the basics has to be listed here or the browser blocks "
                "the request before it ever leaves.  Authorization and Content-Type "
                "cover most APIs.  Add your own X- headers if you use them."
            ),
            use_cases=["Authorization for token auth", "Content-Type for JSON posts"],
            example="Authorization, Content-Type, X-Request-Id",
            example_config='add_header Access-Control-Allow-Headers "Authorization, Content-Type" always;',
        ),
    ),

    Feature(
        key="cors_allow_credentials",
        label="Allow credentials",
        category="headers",
        directive="",
        contexts=("server",),
        type="bool",
        default=False,
        depends_on="cors_enabled",
        help=HelpText(
            summary="Let cross site requests carry cookies and auth headers.",
            detail=(
                "Needed for cookie based sessions across sites.  You must list real "
                "origins when you use this, since * plus credentials is not allowed."
            ),
            use_cases=["A frontend on one domain using cookie sessions from an API on another"],
            example="On, with specific origins listed",
            example_config='add_header Access-Control-Allow-Credentials "true" always;',
            warning="Never pair this with an allowed origin of *.",
        ),
    ),
)


# ==============================================================================
# TLS
# ==============================================================================

register(
    Feature(
        key="ssl_protocols",
        label="TLS versions",
        category="tls",
        directive="ssl_protocols",
        contexts=("server",),
        type="multiselect",
        default=["TLSv1.3"],
        options=[
            ("TLSv1", "TLS 1.0 (broken, do not use)"),
            ("TLSv1.1", "TLS 1.1 (broken, do not use)"),
            ("TLSv1.2", "TLS 1.2"),
            ("TLSv1.3", "TLS 1.3 (best)"),
        ],
        module="http_ssl_module",
        help=HelpText(
            summary="Which TLS versions clients may use.",
            detail=(
                "TLS 1.2 and 1.3 only.  1.0 and 1.1 are broken, every browser dropped "
                "them years ago, and PCI will fail you for having them on.\n\n"
                "1.3 is faster as well as safer.  It cuts a full round trip out of the "
                "handshake, which is noticeable on a phone."
            ),
            use_cases=["TLS 1.2 and 1.3 for everything", "1.3 only for an internal API with modern clients"],
            example="TLSv1.2 and TLSv1.3",
            example_config="ssl_protocols TLSv1.2 TLSv1.3;",
            docs_url=f"{D}/http/ngx_http_ssl_module.html#ssl_protocols",
        ),
    ),

    Feature(
        key="ssl_ciphers",
        label="Cipher list",
        category="tls",
        directive="ssl_ciphers",
        contexts=("server",),
        type="string",
        default="ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305",
        module="http_ssl_module",
        advanced=True,
        help=HelpText(
            summary="Which encryption algorithms are allowed, for TLS 1.2.",
            detail=(
                "TLS 1.3 ignores this completely, it has its own short fixed list that "
                "is all good.  This only applies to 1.2.\n\n"
                "The default here is the Mozilla intermediate list.  All forward secret, "
                "all modern.  Unless you have a specific reason, leave it alone.  Hand "
                "written cipher strings are how people accidentally turn on something "
                "broken."
            ),
            use_cases=["Leave the default", "Change only to meet a specific compliance list"],
            example="The Mozilla intermediate list, which is what is filled in",
            example_config="ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;",
            docs_url=f"{D}/http/ngx_http_ssl_module.html#ssl_ciphers",
        ),
    ),

    Feature(
        key="ssl_ciphersuites",
        min_version=(1, 19, 4),
        label="TLS 1.3 cipher suites",
        category="tls",
        directive="ssl_conf_command",
        contexts=("server",),
        type="string",
        default="TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256",
        module="http_ssl_module",
        advanced=True,
        depends_on="ssl_protocols",
        help=HelpText(
            summary="Which cipher suites TLS 1.3 may use.  Separate from the 1.2 list.",
            detail=(
                "TLS 1.3 threw out the old cipher machinery and started again, so it "
                "ignores the cipher list above completely.  These are its own, and there "
                "are only five in the whole protocol.  All five are good, which is the "
                "point of the redesign.\n\n"
                "Written out only when TLS 1.3 is switched on, since the directive means "
                "nothing otherwise.  The same goes the other way: turn 1.3 on on its own "
                "and the 1.2 cipher list stops being written, because it would sit there "
                "looking like it was doing something.\n\n"
                "The default is the three with hardware acceleration on anything current. "
                "The two left out are the CCM ones, which are for small embedded chips "
                "with no AES instructions and are slower everywhere else."
            ),
            use_cases=[
                "Leave the default",
                "Drop to one suite for a compliance list that names it",
            ],
            example="The three fast ones, which is what is filled in",
            example_config="ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384;",
            docs_url=f"{D}/http/ngx_http_ssl_module.html#ssl_conf_command",
        ),
    ),

    Feature(
        key="ssl_post_quantum_only",
        min_version=(1, 19, 4),
        label="Require post-quantum key exchange",
        category="tls",
        directive="ssl_conf_command",
        contexts=("server",),
        type="bool",
        default=False,
        module="http_ssl_module",
        advanced=True,
        confirm=(
            "This turns visitors away.\n\n"
            "Only X25519MLKEM768 will be offered, with no fallback, so anything that "
            "cannot do it will not connect at all.  That means roughly Chrome and Edge "
            "before 131, Firefox before 132, most phones more than a year old, and "
            "anything scripted against OpenSSL older than 3.5, which includes most "
            "monitoring and a lot of curl.\n\n"
            "It also moves this site to TLS 1.3 only, because the exchange does not "
            "exist in 1.2 and leaving 1.2 on would let a client opt straight back out.\n\n"
            "The people it turns away see a handshake failure that says nothing about "
            "key exchange, so they will not be able to tell you what is wrong.\n\n"
            "Turn this on only where you control every client."
        ),
        help=HelpText(
            summary="Refuse anything that cannot do the quantum resistant exchange.",
            detail=(
                "The setting above offers the quantum resistant exchange and lets a "
                "client that does not know it fall back to a classic curve.  That is the "
                "right default and it protects nobody who falls back.\n\n"
                "This one removes the fallback.  Only X25519MLKEM768 is offered, so a "
                "client that cannot do it does not get a connection at all.  That is the "
                "whole point: harvest now decrypt later does not care that most of your "
                "traffic was protected.\n\n"
                "Turning this on moves TLS to 1.3 only, and the page will show that.  It "
                "is not a side effect to work around, it is the only honest answer: the "
                "quantum resistant exchange exists only in 1.3, so leaving 1.2 switched "
                "on would let any client opt straight back out of the thing you just "
                "insisted on.\n\n"
                "Know what this costs before you turn it on.  Support is recent, roughly "
                "Chrome and Edge 131, Firefox 132, and OpenSSL 3.5 for anything scripted. "
                "Older phones, older curl, and most embedded clients will simply fail to "
                "connect, and the error they show will not mention key exchange."
            ),
            use_cases=[
                "An internal service where you control every client",
                "Data that has to stay secret for longer than the machines that will attack it",
            ],
            example="Off unless you know every client is recent",
            example_config="ssl_conf_command Groups X25519MLKEM768;",
            docs_url=f"{D}/http/ngx_http_ssl_module.html#ssl_conf_command",
        ),
    ),

    Feature(
        key="ssl_post_quantum",
        min_version=(1, 19, 4),
        label="Post-quantum key exchange",
        category="tls",
        directive="ssl_conf_command",
        contexts=("server",),
        type="bool",
        default=True,
        module="http_ssl_module",
        help=HelpText(
            summary="Offer a key exchange that holds up against a future quantum computer.",
            detail=(
                "The worry is real and it is called harvest now, decrypt later.  Somebody "
                "records your encrypted traffic today and sits on it until a quantum "
                "computer can break it.  For anything that has to stay private for years, "
                "that is a problem right now, not later.\n\n"
                "X25519MLKEM768 is a hybrid.  It does both the classic exchange and the "
                "quantum resistant one and mixes the results, so it is at least as strong "
                "as what you had.  Nothing to lose.\n\n"
                "The installer builds nginx against OpenSSL 3.5, which is where this "
                "comes from.  Clients that do not understand it fall back to a normal "
                "curve without any trouble."
            ),
            use_cases=[
                "Anything carrying data that has to stay secret for years",
                "Getting ahead of a compliance requirement that is coming",
            ],
            example="On.  Old clients quietly fall back.",
            example_config="ssl_conf_command Groups X25519MLKEM768:X25519:secp256r1:secp384r1;",
            docs_url=f"{D}/http/ngx_http_ssl_module.html#ssl_conf_command",
        ),
    ),

    Feature(
        key="ssl_session_timeout",
        label="Session cache timeout",
        category="tls",
        directive="ssl_session_timeout",
        contexts=("server",),
        type="time",
        default="1d",
        module="http_ssl_module",
        advanced=True,
        help=HelpText(
            summary="How long a client can resume a TLS session instead of doing a full handshake.",
            detail=(
                "Resuming skips the expensive part of the handshake.  On a site people "
                "come back to during the day, this is a real speed and CPU win."
            ),
            use_cases=["1d for a normal site"],
            example="1d",
            example_config="ssl_session_timeout 1d;\nssl_session_cache shared:SSL:10m;",
            docs_url=f"{D}/http/ngx_http_ssl_module.html#ssl_session_timeout",
        ),
    ),

    Feature(
        key="ssl_session_tickets",
        label="Session tickets",
        category="tls",
        directive="ssl_session_tickets",
        contexts=("server",),
        type="bool",
        default=False,
        module="http_ssl_module",
        advanced=True,
        help=HelpText(
            summary="Let clients hold their own resumable session, rather than the server keeping it.",
            detail=(
                "Off is the safer choice and that is the default here.  The problem is "
                "the ticket key.  If it does not get rotated, and by default nginx does "
                "not rotate it, anybody who later gets that key can decrypt every "
                "recorded session that used it.  That undoes forward secrecy.\n\n"
                "The shared session cache does the same job without the risk."
            ),
            use_cases=["Leave it off unless you rotate ticket keys properly"],
            example="Off",
            example_config="ssl_session_tickets off;",
            docs_url=f"{D}/http/ngx_http_ssl_module.html#ssl_session_tickets",
        ),
    ),

    Feature(
        key="ssl_stapling",
        label="OCSP stapling",
        category="tls",
        directive="ssl_stapling",
        contexts=("server",),
        type="bool",
        default=True,
        module="http_ssl_module",
        help=HelpText(
            summary="Include proof the certificate is not revoked, so the browser does not go ask.",
            detail=(
                "Without it, browsers may go check with the certificate authority "
                "themselves, which adds a round trip to a third party server before your "
                "page loads.  When that server is slow, your site is slow, and there is "
                "nothing you can do about it.\n\n"
                "Stapling means nginx fetches that proof ahead of time and hands it over "
                "during the handshake.  Faster, and it stops the CA seeing who visits "
                "your site."
            ),
            use_cases=["Every public https site"],
            example="On, with a resolver set so nginx can look up the OCSP server",
            example_config=(
                "ssl_stapling on;\n"
                "ssl_stapling_verify on;\n"
                "ssl_trusted_certificate /etc/letsencrypt/live/www.example.com/chain.pem;\n"
                "resolver 1.1.1.1 8.8.8.8 valid=300s;"
            ),
            docs_url=f"{D}/http/ngx_http_ssl_module.html#ssl_stapling",
        ),
    ),

    Feature(
        key="ssl_verify_client",
        label="Require a client certificate",
        category="tls",
        directive="ssl_verify_client",
        contexts=("server",),
        type="select",
        default="off",
        options=[
            ("off", "No client certificate needed"),
            ("on", "Require a valid client certificate"),
            ("optional", "Ask for one, allow the request either way"),
        ],
        module="http_ssl_module",
        advanced=True,
        help=HelpText(
            summary="Mutual TLS.  Make clients prove who they are with a certificate.",
            detail=(
                "Much stronger than a password or an API key, because there is nothing "
                "to phish and nothing to accidentally paste into a chat.  The client "
                "either holds a key signed by your CA or it does not get in.\n\n"
                "You need your own internal CA to issue client certs, and you need a plan "
                "for handing them out and revoking them.  That is the real cost.\n\n"
                "'optional' is useful when you want to allow both and let the app decide "
                "based on whether a cert showed up."
            ),
            use_cases=[
                "A partner API where only a handful of known systems should connect",
                "An admin panel locked to company issued device certs",
                "Machine to machine traffic with no human involved",
            ],
            example="on, with your internal CA in ssl_client_certificate",
            example_config=(
                "ssl_verify_client on;\n"
                "ssl_client_certificate /etc/nginx/client-ca.crt;\n"
                "ssl_verify_depth 2;\n\n"
                "# pass who they are through to the backend\n"
                "proxy_set_header X-Client-DN $ssl_client_s_dn;\n"
                "proxy_set_header X-Client-Verify $ssl_client_verify;"
            ),
            docs_url=f"{D}/http/ngx_http_ssl_module.html#ssl_verify_client",
        ),
    ),
)


# ==============================================================================
# Static files
# ==============================================================================

register(
    Feature(
        key="autoindex",
        label="Directory listing",
        category="static",
        directive="autoindex",
        contexts=("server", "location"),
        type="bool",
        default=False,
        help=HelpText(
            summary="Show a list of files when there is no index page.",
            detail=(
                "Handy for an internal file share.  A bad idea on anything public, "
                "because it shows every file in the folder including ones you forgot "
                "were there, like backups and old config files."
            ),
            use_cases=["An internal download folder", "A package repository mirror"],
            example="Off for public sites",
            example_config="autoindex on;\nautoindex_exact_size off;\nautoindex_localtime on;",
            docs_url=f"{D}/http/ngx_http_autoindex_module.html",
            warning="Never turn this on for a public site without knowing exactly what is in the folder.",
        ),
    ),

    Feature(
        key="fancyindex",
        label="Pretty directory listing",
        category="static",
        directive="fancyindex",
        contexts=("server", "location"),
        type="bool",
        default=False,
        module="ngx-fancyindex",
        advanced=True,
        help=HelpText(
            summary="A directory listing that does not look like it is from 1996.",
            detail=(
                "Same job as autoindex but you can style it, add a header and footer, and "
                "sort the columns.  The installer compiles this module in.\n\n"
                "Same warning applies.  It still lists every file in the folder."
            ),
            use_cases=["An internal file share you want to look presentable"],
            example="On, with a custom header file",
            example_config=(
                "fancyindex on;\n"
                "fancyindex_exact_size off;\n"
                "fancyindex_localtime on;"
            ),
            docs_url="https://github.com/aperezdc/ngx-fancyindex",
        ),
    ),

    Feature(
        key="expires",
        label="Browser cache time",
        category="static",
        directive="expires",
        contexts=("server", "location"),
        type="string",
        default="",
        placeholder="30d",
        help=HelpText(
            summary="How long browsers should keep a copy before asking again.",
            detail=(
                "Sets Cache-Control and Expires.  For assets with a hash in the filename, "
                "like app.a1b2c3.js, you can set this to a year, because the name changes "
                "whenever the content does.\n\n"
                "Be careful with anything that keeps the same name.  Set a long time on "
                "logo.png and you cannot change that logo for a year on anybody who has "
                "already seen it."
            ),
            use_cases=[
                "1y for hashed build assets",
                "30d for images that rarely change",
                "epoch for anything that must never be cached",
            ],
            example="30d, or 1y for hashed filenames",
            example_config="expires 30d;\nadd_header Cache-Control \"public, immutable\";",
            docs_url=f"{D}/http/ngx_http_headers_module.html#expires",
        ),
    ),

    Feature(
        key="try_files",
        label="File fallback order",
        category="static",
        directive="try_files",
        contexts=("location",),
        type="string",
        default="",
        multi_arg=True,
        placeholder="$uri $uri/ /index.html",
        help=HelpText(
            summary="Try each of these in order and serve the first one that exists.",
            detail=(
                "This is how you host a single page app.  Try the real file, then the "
                "folder, then fall back to index.html so the app's own router can handle "
                "the URL.  Without it, refreshing on any page except the home page gives "
                "a 404."
            ),
            use_cases=[
                "React, Vue or Angular apps, where the fallback is /index.html",
                "WordPress, where it is /index.php?$args",
            ],
            example="$uri $uri/ /index.html",
            example_config="try_files $uri $uri/ /index.html;",
            docs_url=f"{D}/http/ngx_http_core_module.html#try_files",
        ),
    ),

    Feature(
        key="sendfile",
        label="Use sendfile",
        category="static",
        directive="sendfile",
        contexts=("server", "location"),
        type="bool",
        default=True,
        advanced=True,
        help=HelpText(
            summary="Let the kernel copy files straight to the network.",
            detail=(
                "Normally serving a file means reading it into nginx's memory and then "
                "writing it back out.  sendfile skips that trip and hands it off inside "
                "the kernel.  Meaningfully faster for static files.\n\n"
                "Turn it off if you are serving files from a network filesystem like NFS, "
                "where it can misbehave."
            ),
            use_cases=["On for local disk", "Off for NFS or some VM shared folders"],
            example="On",
            example_config="sendfile on;\ntcp_nopush on;",
            docs_url=f"{D}/http/ngx_http_core_module.html#sendfile",
        ),
    ),

    Feature(
        key="open_file_cache",
        label="Cache file lookups",
        category="static",
        directive="open_file_cache",
        contexts=("server", "location"),
        type="bool",
        default=False,
        advanced=True,
        help=HelpText(
            summary="Remember file handles and whether files exist, so nginx stops asking the disk.",
            detail=(
                "On a site serving a lot of small static files this cuts a surprising "
                "amount of system call overhead.\n\n"
                "The catch is staleness.  Deploy new files and nginx may keep serving the "
                "old ones until the cache entry ages out.  Keep the valid time short or "
                "make your deploy reload nginx."
            ),
            use_cases=["A busy static file site", "A CDN origin server"],
            example="Cache 10000 entries, drop anything unused for 20s",
            example_config=(
                "open_file_cache max=10000 inactive=20s;\n"
                "open_file_cache_valid 30s;\n"
                "open_file_cache_min_uses 2;\n"
                "open_file_cache_errors on;"
            ),
            docs_url=f"{D}/http/ngx_http_core_module.html#open_file_cache",
            warning="Deploys can serve stale files until the cache expires.  Reload nginx after a deploy.",
        ),
    ),
)


# ==============================================================================
# WebSocket
# ==============================================================================

register(
    Feature(
        key="websocket_enabled",
        label="Enable WebSocket support",
        category="websocket",
        directive="",
        contexts=("server", "location"),
        type="bool",
        default=False,
        help=HelpText(
            summary="Let connections upgrade from http to a WebSocket.",
            detail=(
                "A WebSocket starts life as a normal http request with an Upgrade header "
                "and then turns into a long lived two way connection.  Proxying it needs "
                "three things, and missing any one of them breaks it:\n\n"
                "  HTTP/1.1 to the backend, since 1.0 has no upgrade\n"
                "  The Upgrade and Connection headers passed through\n"
                "  A long read timeout, or the connection dies after a minute\n\n"
                "Turning this on sets all three for you.  If your WebSocket connects and "
                "then drops after exactly 60 seconds, it is the timeout, every time."
            ),
            use_cases=[
                "A chat or messaging feature",
                "Live dashboards that push updates",
                "Anything using socket.io or SignalR",
            ],
            example="On, with the read timeout raised to an hour",
            example_config=(
                "proxy_http_version 1.1;\n"
                "proxy_set_header Upgrade $http_upgrade;\n"
                "proxy_set_header Connection \"upgrade\";\n"
                "proxy_read_timeout 3600s;\n"
                "proxy_send_timeout 3600s;"
            ),
            docs_url=f"{D}/http/websocket.html",
        ),
    ),

    Feature(
        key="websocket_timeout",
        label="WebSocket idle timeout",
        category="websocket",
        directive="",
        contexts=("server", "location"),
        type="time",
        default="3600s",
        depends_on="websocket_enabled",
        help=HelpText(
            summary="How long a WebSocket can sit quiet before nginx closes it.",
            detail=(
                "Make it longer than whatever your app uses for its heartbeat ping.  If "
                "the app pings every 30 seconds and this is 20 seconds, nginx cuts the "
                "connection between pings and the client reconnects forever."
            ),
            use_cases=["3600s for a chat app", "86400s for a long running dashboard"],
            example="3600s",
            example_config="proxy_read_timeout 3600s;",
        ),
    ),
)


# ==============================================================================
# Logging
# ==============================================================================

register(
    Feature(
        key="access_log_enabled",
        label="Access log",
        category="logging",
        directive="",
        contexts=("server", "location"),
        type="bool",
        default=True,
        help=HelpText(
            summary="Write a line for every request.",
            detail=(
                "You want this on almost everywhere.  Turning it off on high volume "
                "paths that you do not care about, like a health check endpoint hit "
                "every second, keeps the log readable and saves disk."
            ),
            use_cases=["On for normal traffic", "Off for health check and static asset paths"],
            example="On, off for /healthz",
            example_config="access_log /var/log/nginx/www.example.com.access.log main;",
            docs_url=f"{D}/http/ngx_http_log_module.html#access_log",
        ),
    ),

    Feature(
        key="access_log_format",
        label="Log format",
        category="logging",
        directive="",
        contexts=("server", "location"),
        type="select",
        default="main",
        options=[
            ("main", "Standard combined format"),
            ("detailed", "Adds timings and upstream info"),
            ("json", "JSON, one object per line"),
        ],
        depends_on="access_log_enabled",
        help=HelpText(
            summary="What shape the log lines take.",
            detail=(
                "The detailed format adds the two numbers you actually need when "
                "somebody says the site is slow: how long nginx took overall, and how "
                "long the backend took.  The difference between them tells you which one "
                "to go look at.\n\n"
                "JSON is the right pick if the logs go into a log system.  No parsing "
                "rules to write and nothing breaks when a field has a space in it."
            ),
            use_cases=[
                "detailed when chasing down slowness",
                "json when shipping to a log platform",
            ],
            example="detailed",
            example_config=(
                "log_format detailed '$remote_addr - $remote_user [$time_local] '\n"
                "    '\"$request\" $status $body_bytes_sent '\n"
                "    'rt=$request_time uct=$upstream_connect_time '\n"
                "    'uht=$upstream_header_time urt=$upstream_response_time '\n"
                "    'upstream=$upstream_addr cache=$upstream_cache_status';"
            ),
            docs_url=f"{D}/http/ngx_http_log_module.html#log_format",
        ),
    ),

    Feature(
        key="error_log_level",
        label="Error log level",
        category="logging",
        directive="",
        contexts=("server",),
        type="select",
        default="warn",
        options=[
            ("debug", "debug (huge, only when chasing a bug)"),
            ("info", "info"),
            ("notice", "notice"),
            ("warn", "warn (recommended)"),
            ("error", "error"),
            ("crit", "crit"),
        ],
        help=HelpText(
            summary="How much detail goes in the error log.",
            detail=(
                "warn is the right normal setting.  debug is enormous, easily gigabytes "
                "an hour on a busy site, and it will fill your disk overnight.  Use it "
                "while you are actively looking at something and then put it back."
            ),
            use_cases=["warn day to day", "debug for a short window while troubleshooting"],
            example="warn",
            example_config="error_log /var/log/nginx/www.example.com.error.log warn;",
            docs_url=f"{D}/ngx_core_module.html#error_log",
            warning="Leaving this on debug will fill the disk and take the site down with it.",
        ),
    ),

    Feature(
        key="log_not_found",
        label="Log missing files",
        category="logging",
        directive="log_not_found",
        contexts=("server", "location"),
        type="bool",
        default=True,
        advanced=True,
        help=HelpText(
            summary="Whether a missing file writes a line to the error log.",
            detail=(
                "Turn it off for things that are missing on purpose and constantly "
                "requested, like favicon.ico or robots.txt.  Otherwise the error log "
                "fills with noise and you stop reading it, which is worse."
            ),
            use_cases=["Off for favicon.ico and robots.txt"],
            example="Off on those specific paths",
            example_config="location = /favicon.ico {\n    log_not_found off;\n    access_log off;\n}",
            docs_url=f"{D}/http/ngx_http_core_module.html#log_not_found",
        ),
    ),
)


# ==============================================================================
# Advanced
# ==============================================================================

register(
    Feature(
        key="error_pages",
        label="Custom error pages",
        category="advanced",
        directive="error_page",
        contexts=("server",),
        type="list",
        default=[],
        help=HelpText(
            summary="Show your own page instead of the default nginx error.",
            detail=(
                "One rule per line: the codes, then the page.  The stock nginx error "
                "page is ugly and says nginx on it, which you probably do not want on a "
                "public site.\n\n"
                "For backend errors you also need to turn on proxy_intercept_errors, "
                "over in the Proxy section, or the backend's own error page goes straight "
                "through."
            ),
            use_cases=["A branded 404", "A friendly maintenance page for 502 and 503"],
            example="404 /404.html and then 500 502 503 504 /50x.html",
            example_config=(
                "error_page 404 /404.html;\n"
                "error_page 500 502 503 504 /50x.html;\n\n"
                "location = /50x.html {\n"
                "    root /usr/share/nginx/html;\n"
                "    internal;\n"
                "}"
            ),
            docs_url=f"{D}/http/ngx_http_core_module.html#error_page",
        ),
    ),

    Feature(
        key="rewrite_rules",
        label="Rewrite rules",
        category="advanced",
        directive="rewrite",
        contexts=("server", "location"),
        type="list",
        regex_values=True,
        default=[],
        advanced=True,
        help=HelpText(
            summary="Change the URL with a regular expression.  One rule per line.",
            detail=(
                "Powerful and easy to shoot yourself with.  A rewrite that matches its "
                "own output loops until nginx gives up with a 500.\n\n"
                "Most of the time you do not need a rewrite at all.  A plain redirect or "
                "a try_files does the job with far less to go wrong.  Reach for this when "
                "you actually need a pattern."
            ),
            use_cases=[
                "Moving an old URL scheme to a new one after a redesign",
                "Stripping a path prefix before it reaches the backend",
            ],
            # Everything after the word "rewrite", one rule per line.
            example="^/old/(.*)$ /new/$1 permanent",
            example_config="rewrite ^/old/(.*)$ /new/$1 permanent;",
            docs_url=f"{D}/http/ngx_http_rewrite_module.html#rewrite",
            warning="A rule whose output matches its own pattern loops forever and returns 500.",
        ),
    ),

    Feature(
        key="sub_filter_rules",
        label="Response text replacement",
        category="advanced",
        directive="sub_filter",
        contexts=("server", "location"),
        type="list",
        regex_values=True,
        default=[],
        module="http_sub_module",
        advanced=True,
        help=HelpText(
            summary="Find and replace text in the response as it goes out.",
            detail=(
                "Rewrites the body on the fly.  Useful for fixing hardcoded URLs coming "
                "out of an application you cannot change.\n\n"
                "It costs CPU on every response and it cannot work on compressed content, "
                "so nginx has to ask the backend for uncompressed output.  Treat it as a "
                "workaround, not a design."
            ),
            use_cases=[
                "Fixing absolute http:// links from a legacy app that does not know it is behind TLS",
                "Swapping an internal hostname for the public one in returned HTML",
            ],
            # Everything after "sub_filter": the search and replacement
            # strings, both quoted.  The example must be literally typeable.
            example="'http://internal.example.com' 'https://www.example.com'",
            example_config=(
                "sub_filter 'http://internal.example.com' 'https://www.example.com';\n"
                "sub_filter_once off;\n"
                "sub_filter_types text/html text/css application/javascript;"
            ),
            docs_url=f"{D}/http/ngx_http_sub_module.html",
        ),
    ),

    Feature(
        key="resolver",
        label="DNS resolver",
        category="advanced",
        directive="resolver",
        contexts=("server",),
        type="string",
        default="",
        multi_arg=True,
        placeholder="1.1.1.1 8.8.8.8 valid=300s",
        # Deliberately not advanced.  Without it nginx resolves backend
        # hostnames only at startup, so a backend whose address changes
        # silently breaks until the next reload.
        advanced=False,
        help=HelpText(
            summary="Which DNS servers nginx uses when it has to look something up at runtime.",
            detail=(
                "Here is the thing that surprises everybody.  nginx resolves the "
                "hostnames in your config once, at startup, and then never again.  If a "
                "backend's IP changes, nginx keeps talking to the old one until you "
                "reload it.\n\n"
                "That bites hard with cloud backends whose addresses move on their own.  "
                "Setting a resolver, plus using a variable in the proxy_pass, makes nginx "
                "look the name up as it goes.\n\n"
                "OCSP stapling needs a resolver too, or it silently does nothing."
            ),
            use_cases=[
                "Backends behind a cloud load balancer whose IP changes",
                "Required for OCSP stapling to work at all",
            ],
            example="1.1.1.1 8.8.8.8 valid=300s ipv6=off",
            example_config=(
                "resolver 1.1.1.1 8.8.8.8 valid=300s ipv6=off;\n"
                "resolver_timeout 5s;\n\n"
                "# a variable in proxy_pass is what forces the runtime lookup\n"
                "set $backend \"api.internal.example.com\";\n"
                "proxy_pass https://$backend;"
            ),
            docs_url=f"{D}/http/ngx_http_core_module.html#resolver",
        ),
    ),

    Feature(
        key="proxy_cookie_path",
        label="Rewrite cookie paths",
        category="proxy",
        directive="proxy_cookie_path",
        contexts=("server", "location"),
        type="string",
        default="",
        multi_arg=True,
        help=HelpText(
            summary="Fix the Path on cookies from a backend served under a "
                    "different path than the one your visitors use.",
            detail=(
                "Needed whenever you proxy an application that lives under a "
                "sub path to the root of a site.  Guacamole under /guacamole/, "
                "Jenkins under /jenkins/, almost anything on Tomcat.\n\n"
                "The application sets its session cookie with Path=/guacamole/ "
                "because that is where it thinks it is.  Your visitor is at "
                "the root of the site, so the browser decides the cookie does "
                "not apply and never sends it back.  The symptom is the "
                "clearest one in proxying: the login page works, the login "
                "itself works, and then every page after it says you are "
                "logged out.  Nothing errors and nothing appears in a log.\n\n"
                "Two arguments: the path the backend sets, then the path it "
                "should become."
            ),
            use_cases=[
                "Guacamole, Jenkins or anything else on Tomcat proxied at /",
                "A backend moved behind a path your visitors do not see",
            ],
            example="/guacamole/ /",
            example_config="proxy_cookie_path /guacamole/ /;",
            warning=(
                "Its partner is usually needed too.  If the application sends "
                "redirects it will point them at its own path, and those need "
                "rewriting as well, which nginx does with proxy_redirect."
            ),
            docs_url=f"{D}/http/ngx_http_proxy_module.html#proxy_cookie_path",
        ),
    ),

    Feature(
        key="backend_path",
        label="Backend lives under this path",
        category="proxy",
        directive="proxy_pass",
        contexts=("server", "location"),
        type="string",
        default="",
        pattern=r"^/",
        placeholder="/shop/",
        help=HelpText(
            summary="The application is not at the root of the backend.  Say "
                    "where it is and we put the path on for you.",
            detail=(
                "The opposite of taking a prefix off.  Your visitors ask for "
                "/basket and the backend wants /shop/basket, because the "
                "application is installed under a path or sits behind a token "
                "in the URL.\n\n"
                "Set it here rather than writing a rewrite rule.  A rewrite "
                "rule for this has to go at the site level, which means it "
                "runs before nginx has picked a location and so rewrites "
                "everything: the certificate challenge and your error pages "
                "included.  People then carve those back out with a negative "
                "lookahead and the site works until the next thing gets added "
                "that also needs carving out.\n\n"
                "This goes on proxy_pass instead, inside the one location that "
                "proxies, so nothing else on the site can see it.  The matching "
                "proxy_redirect is written for you, so a backend that redirects "
                "to its own path does not push the path into your visitor's "
                "address bar.  Anything you set yourself is written first and "
                "still wins."
            ),
            use_cases=[
                "An application installed under /app on the backend",
                "A backend that expects a fixed token or tenant in the path",
            ],
            example="/shop/",
            example_config="proxy_pass http://your_pool/shop/;",
            docs_url=f"{D}/http/ngx_http_proxy_module.html#proxy_pass",
        ),
    ),

    Feature(
        key="proxy_redirect",
        label="Rewrite redirect locations",
        category="proxy",
        directive="proxy_redirect",
        contexts=("server", "location"),
        type="string",
        default="",
        multi_arg=True,
        help=HelpText(
            summary="Fix the Location header when a backend redirects to its "
                    "own address or path rather than yours.",
            detail=(
                "The other half of proxying an application that lives "
                "somewhere other than where your visitors think it does.  A "
                "backend that redirects to http://localhost:8080/guacamole/ "
                "sends the visitor's browser to a machine that is not there.\n\n"
                "Two arguments: what the backend says, and what it should say "
                "instead.  Leave this empty and nginx does its default, which "
                "rewrites redirects pointing at the proxied address and leaves "
                "everything else alone, and that is right more often than not."
            ),
            use_cases=[
                "A backend under a sub path that redirects to its own path",
                "An application that redirects to its internal hostname",
            ],
            example="/guacamole/ /",
            example_config="proxy_redirect /guacamole/ /;",
            docs_url=f"{D}/http/ngx_http_proxy_module.html#proxy_redirect",
        ),
    ),

    Feature(
        key="http3_enabled",
        label="HTTP/3 (QUIC)",
        category="tls",
        directive="",
        contexts=("server",),
        type="bool",
        default=False,
        module="http_v3_module",
        help=HelpText(
            summary="Offer HTTP/3 over QUIC as well as HTTP/2, on the same port.",
            detail=(
                "QUIC runs over UDP rather than TCP, which removes a round trip "
                "from the handshake and stops one lost packet stalling every "
                "stream on the connection.  On a slow or lossy network that is "
                "the difference people actually notice.\n\n"
                "Nothing is taken away by turning it on.  A browser still "
                "connects over TCP first and only moves to QUIC because the "
                "response advertised it, so anything that cannot speak HTTP/3 "
                "carries on exactly as before.\n\n"
                "It matters here for a second reason.  The post quantum key "
                "exchange is a TLS 1.3 feature, and a QUIC handshake is TLS 1.3 "
                "by definition, so this is the path where a captured handshake "
                "is hardest to decrypt later."
            ),
            use_cases=[
                "A site with visitors on mobile networks",
                "Anywhere latency matters more than throughput",
            ],
            example="on",
            example_config=(
                "listen 443 quic reuseport;\n"
                "http3 on;\n"
                "add_header Alt-Svc 'h3=\":443\"; ma=86400' always;"
            ),
            warning=(
                "UDP on this port has to be open.  QUIC is UDP, and a firewall "
                "that allows TCP 443 and nothing else will let the site keep "
                "working over HTTP/2 while HTTP/3 silently never connects, "
                "which looks like the setting doing nothing."
            ),
            docs_url=f"{D}/http/ngx_http_v3_module.html",
        ),
    ),

    Feature(
        key="waf_mode",
        own_screen=True,
        label="WAF",
        category="security",
        directive="",            # renderer writes several lines
        contexts=("server",),
        type="select",
        default="off",
        module="modsecurity",
        options=[
            ("off", "Off"),
            ("watching", "Watching, refuse nothing"),
            ("block_known", "Block known malicious"),
            ("block", "Block what the attack rules catch"),
        ],
        help=HelpText(
            summary="Check requests against the OWASP rules, and choose how much to refuse.",
            detail=(
                "Four settings, and the order matters.\n\n"
                "Watching checks every request and refuses none of them.  It is where "
                "you start, and it is the only one that is safe to turn on without "
                "knowing anything about the site, because the worst it can do is fill "
                "a log.\n\n"
                "Block known malicious refuses the traffic that is obviously an "
                "attack and nothing else.  It is not a hand picked list of attacks: "
                "the rules score each request, and this sets the bar high enough that "
                "only a request tripping several rules, or one serious one, is "
                "refused.  One odd looking header never is.  That is why it can go on "
                "without tuning.\n\n"
                "Block what the rules say applies the full rule set.  It will refuse "
                "things your own application does until you have told it not to, so "
                "run watching first, exercise the site, and turn the false positives "
                "into exclusions.  Going straight here is how people end up switching "
                "a WAF off at two in the morning.\n\n"
                "Whatever you pick, the rules have to be on every node.  A node "
                "without them refuses the whole config, so install them from Settings "
                "first."
            ),
            use_cases=[
                "Watching a new site to find out what the rules would refuse",
                "Blocking obvious attacks on a site nobody has time to tune",
                "Full blocking on a site whose false positives have been dealt with",
            ],
            example="watching",
            example_config=(
                "modsecurity on;\n"
                "modsecurity_rules_file /etc/nginx/nginxmgr/waf/example-com.conf;"
            ),
            warning=(
                "Not free.  The rules cost real time on every request and tens of "
                "megabytes per worker, so watch the Utilization page after turning it "
                "on rather than finding out under load."
            ),
            docs_url="https://coreruleset.org/docs/",
        ),
    ),

    Feature(
        key="waf_positive",
        own_screen=True,
        label="Allowed surface",
        category="security",
        directive="",
        contexts=("server",),
        type="select",
        default="off",
        module="modsecurity",
        advanced=True,
        options=[
            ("off", "Off"),
            ("report", "Report what would be refused"),
            ("enforce", "Refuse anything outside the surface"),
        ],
        help=HelpText(
            summary="Allow only the paths this application actually has, and "
                    "refuse everything else.",
            detail=(
                "Everything else in this tab is a negative model: the rules describe "
                "attacks, and anything they do not recognise is allowed.  This is the "
                "other way round.  It holds a list of the paths and methods the "
                "application really has, and refuses anything not on it.\n\n"
                "You build the list by recording a round.  Testers walk every feature "
                "of the site from the addresses you named, and what they reached "
                "becomes a list you review and save into a profile.  Paths that "
                "contain an id are collapsed to a wildcard, so /user/12345/profile "
                "covers the user created tomorrow as well.\n\n"
                "Report first, always.  A positive model is only as complete as the "
                "walk that built it, and the page nobody thought to open is the page "
                "that returns 403 to a real customer.  Report mode logs what it would "
                "have refused and refuses nothing, so you can see the gaps in real "
                "traffic before they cost anything.\n\n"
                "It does not learn parameters, only paths and methods.  Learning "
                "parameter names would mean logging request bodies, and a body is "
                "where passwords and card numbers are."
            ),
            use_cases=[
                "An admin interface with a small, well known set of pages",
                "An API where the routes are fixed and anything else is probing",
                "Any application where you can genuinely walk every feature",
            ],
            example="Record a round, review the paths, run in report for a week, "
                    "then enforce",
            example_config=(
                'SecAction "id:20000,phase:2,nolog,pass,setvar:tx.fw_allowed=0"\n'
                'SecRule REQUEST_FILENAME "@rx ^/about/?$" "id:20001,phase:2,chain,nolog,pass"\n'
                '    SecRule REQUEST_METHOD "@rx ^(?:GET|HEAD)$" "t:none,setvar:tx.fw_allowed=1"\n'
                'SecRule TX:fw_allowed "@eq 0" "id:29999,phase:2,log,deny,status:403"'
            ),
            warning=(
                "Enforcing a surface that is missing a page refuses that page to "
                "everybody.  Run it in report mode until the log is quiet, and read "
                "the log rather than assuming the walk was complete."
            ),
        ),
    ),

    Feature(
        key="waf_paranoia",
        own_screen=True,
        label="WAF strictness",
        category="security",
        directive="",
        contexts=("server",),
        type="select",
        default="1",
        module="modsecurity",
        advanced=True,
        options=[
            ("1", "1, the default"),
            ("2", "2, stricter"),
            ("3", "3, stricter still"),
            ("4", "4, refuses ordinary things"),
        ],
        help=HelpText(
            summary="How suspicious the rules are allowed to be.  Leave this at 1.",
            detail=(
                "The rule set ships four levels.  Level 1 is what it is tuned to be "
                "deployable at, and is what this uses unless you change it.\n\n"
                "Each level above adds rules that catch more and are wrong more "
                "often.  Level 4 refuses things a normal application does every day.  "
                "Raising this is not a way to be more secure for free; it is a "
                "commitment to spend time on the false positives it produces, and it "
                "should be done in watching mode first.\n\n"
                "Only does anything when the WAF above is not off."
            ),
            use_cases=[
                "A site holding something worth the tuning time",
            ],
            example="1",
            warning=(
                "Expect to spend time tuning anything above 1.  Raise it in watching "
                "mode and look at what fires before you let it refuse anything."
            ),
            docs_url="https://coreruleset.org/docs/concepts/paranoia_levels/",
        ),
    ),

    Feature(
        key="geoip2_country_block",
        own_screen=True,
        label="Block by country",
        category="access",
        directive="",
        contexts=("server",),
        type="list",
        default=[],
        module="geoip2",
        advanced=True,
        help=HelpText(
            summary="Refuse requests from certain countries.  Two letter codes, one per line.",
            detail=(
                "Needs a MaxMind GeoLite2 database on the box, and it needs updating "
                "every so often or the answers drift.\n\n"
                "Know what this actually buys you.  A VPN defeats it in one click, so it "
                "does not stop anybody who is trying.  What it does do is cut a lot of "
                "automated scanning noise, and it can satisfy a compliance rule that says "
                "only serve certain regions.  Do not treat it as a security control."
            ),
            use_cases=[
                "A regional site with a rule about where it may be served",
                "Cutting down scanner traffic from places you have no users",
            ],
            example="CN, RU, KP",
            example_config=(
                "geoip2 /usr/share/GeoIP/GeoLite2-Country.mmdb {\n"
                "    $geoip2_country_code country iso_code;\n"
                "}\n\n"
                "map $geoip2_country_code $blocked_country {\n"
                "    default 0;\n"
                "    CN 1;\n"
                "}\n\n"
                "if ($blocked_country) { return 403; }"
            ),
            docs_url="https://github.com/leev/ngx_http_geoip2_module",
            warning="Anybody with a VPN walks straight past this.  It is noise reduction, not security.",
        ),
    ),

# Signed URLs (secure_link) are deliberately not offered.  nginx only
# verifies the links; the backend application has to generate them with the
# same secret and formula.  A checkbox alone would just 403 everything.  Use
# the Custom config box instead, for example:
#
#     location /downloads/ {
#         secure_link $arg_md5,$arg_expires;
#         secure_link_md5 "$secure_link_expires$uri$remote_addr yoursecret";
#         if ($secure_link = "")  { return 403; }
#         if ($secure_link = "0") { return 410; }
#     }
)


# ==============================================================================
# The paid only list
# ==============================================================================
#
# None of these render a control.  They are listed on the comparison page,
# grayed out, with the open source workaround, because the nginx docs make it
# easy to miss that they need a subscription.

register(
    Feature(
        key="_plus_sticky",
        label="Sticky sessions",
        category="proxy",
        edition="plus",
        contexts=(),
        type="bool",
        oss_alternative=(
            "Use ip_hash to pin a client to a backend by their IP address, or use "
            "hash $cookie_yoursessioncookie to pin by a cookie your app already sets.  "
            "The cookie version is better, because ip_hash sends a whole office behind "
            "one NAT address to the same backend, and it re-shuffles everybody whenever "
            "a backend goes down."
        ),
        help=HelpText(
            summary="Keep a user on the same backend using a cookie nginx creates.",
            detail=(
                "Paid feature.  nginx Plus sets its own cookie and reads it to route "
                "each request back to the same server.\n\n"
                "The free version gets close.  ip_hash routes on the client address, and "
                "hash on a cookie routes on something your app already sets, which is "
                "usually the better answer.\n\n"
                "Honestly though, the real fix is to not need it.  Put sessions in redis "
                "or the database so any backend can serve any user.  Then you can take a "
                "server out whenever you want and nobody gets logged out."
            ),
            use_cases=["Legacy apps that keep session state in local memory"],
            example_config=(
                "# free version, pin on a cookie your app already sets\n"
                "upstream app_pool {\n"
                "    hash $cookie_JSESSIONID consistent;\n"
                "    server 10.20.30.51:8080;\n"
                "    server 10.20.30.52:8080;\n"
                "}"
            ),
            docs_url=f"{D}/http/ngx_http_upstream_module.html#sticky",
        ),
    ),

    Feature(
        key="_plus_health_check",
        label="Active health checks in nginx",
        category="proxy",
        edition="plus",
        contexts=(),
        type="bool",
        oss_alternative=(
            "This manager does it instead.  It checks every backend on a schedule from "
            "each node, and when one fails it rewrites the upstream with that server "
            "marked down and reloads nginx.  You get the same result, the checking just "
            "happens out here rather than inside nginx."
        ),
        help=HelpText(
            summary="nginx itself probing backends on a timer.",
            detail=(
                "Paid feature.  The free nginx only notices a backend is bad when a real "
                "request to it fails, which means somebody had to get a slow page or an "
                "error first.\n\n"
                "That is exactly the gap this manager fills.  Set up the checks on the "
                "pool page and it handles the probing and the config rewrite for you."
            ),
            use_cases=["Taking a bad backend out before a user finds it"],
            example_config=(
                "# what the free version can do on its own, passive only\n"
                "upstream app_pool {\n"
                "    server 10.20.30.51:8080 max_fails=3 fail_timeout=10s;\n"
                "    server 10.20.30.52:8080 max_fails=3 fail_timeout=10s;\n"
                "}"
            ),
            docs_url=f"{D}/http/ngx_http_upstream_hc_module.html",
        ),
    ),

    Feature(
        key="_plus_slow_start",
        label="Slow start",
        category="proxy",
        edition="plus",
        contexts=(),
        type="bool",
        oss_alternative=(
            "There is no direct equivalent.  What works in practice is to bring a "
            "recovered backend back with a low weight, wait for it to warm up, then "
            "raise the weight.  You can do that from the pool page in two steps."
        ),
        help=HelpText(
            summary="Ease traffic back onto a server that just came back, instead of all at once.",
            detail=(
                "Paid feature.  Without it, a backend that just recovered immediately "
                "gets its full share of traffic.  For something like a Java app with a "
                "cold JIT and an empty connection pool, that burst can knock it straight "
                "back over, and then you have a server flapping in and out.\n\n"
                "The workaround is manual but it works: set the weight to 1, let it warm "
                "up, then put the weight back."
            ),
            use_cases=["JVM apps that are slow for the first minute after a restart"],
            example_config=(
                "# manual version, bring it back at low weight first\n"
                "server 10.20.30.51:8080 weight=1;   # then raise to 10 once it is warm"
            ),
            docs_url=f"{D}/http/ngx_http_upstream_module.html#slow_start",
        ),
    ),

    Feature(
        key="_plus_least_time",
        label="Least time load balancing",
        category="proxy",
        edition="plus",
        contexts=(),
        type="bool",
        oss_alternative=(
            "Use least_conn.  It sends each request to whichever backend has the fewest "
            "connections open, which tracks response time closely in practice, since a "
            "slow server piles up connections.  random two least_conn is also good and "
            "avoids the herd problem on very large pools."
        ),
        help=HelpText(
            summary="Pick the backend answering fastest right now.",
            detail=(
                "Paid feature in the nginx version this installer builds.\n\n"
                "least_conn gets you most of the way for free.  A server that has gotten "
                "slow accumulates open connections, so least_conn naturally stops picking "
                "it without ever measuring a response time."
            ),
            use_cases=["Pools where backends have noticeably different speeds"],
            example_config="upstream app_pool {\n    least_conn;\n    server 10.20.30.51:8080;\n}",
            docs_url=f"{D}/http/ngx_http_upstream_module.html#least_time",
        ),
    ),

    Feature(
        key="_plus_api",
        label="Runtime API and dashboard",
        category="advanced",
        edition="plus",
        contexts=(),
        type="bool",
        oss_alternative=(
            "This manager is the replacement.  Changing a pool here rewrites the config "
            "and reloads, which on nginx is a graceful operation, so nothing in flight "
            "gets dropped.  For metrics, the free stub_status module gives connection "
            "and request counts and the dashboard reads it."
        ),
        help=HelpText(
            summary="Change upstreams live over an API, with a built in stats dashboard.",
            detail=(
                "Paid feature.  It lets you add and remove backends without touching the "
                "config file.\n\n"
                "A reload in nginx is cheap and graceful.  Old workers finish what they "
                "are doing while new ones pick up the new config, so nobody sees an "
                "error.  Doing it this way costs a little more than an API call and gets "
                "you a config file you can read, diff and roll back, which the API "
                "version does not."
            ),
            use_cases=["Autoscaling groups where backends come and go constantly"],
            example_config="# free version, what the dashboard reads\nstub_status;",
            docs_url=f"{D}/http/ngx_http_api_module.html",
        ),
    ),

    Feature(
        key="_plus_auth_jwt",
        label="JWT validation in nginx",
        category="security",
        edition="plus",
        contexts=(),
        type="bool",
        oss_alternative=(
            "Use auth_request, which is free and built in here.  It sends each request to "
            "a small internal endpoint that validates the token and answers 200 or 401.  "
            "One tiny service, and it works for any auth scheme, not just JWT."
        ),
        help=HelpText(
            summary="Check and validate a JWT before the request reaches your backend.",
            detail=(
                "Paid feature.\n\n"
                "auth_request covers the same ground for free.  nginx makes a subrequest "
                "to an endpoint you write, and only passes the request through if that "
                "endpoint says yes.  A little more moving parts, and more flexible."
            ),
            use_cases=["Checking tokens at the edge instead of in every backend"],
            example_config=(
                "# free version using auth_request\n"
                "location /api/ {\n"
                "    auth_request /_auth;\n"
                "    proxy_pass http://api_pool;\n"
                "}\n\n"
                "location = /_auth {\n"
                "    internal;\n"
                "    proxy_pass http://auth_service/verify;\n"
                "    proxy_pass_request_body off;\n"
                "    proxy_set_header Content-Length \"\";\n"
                "    proxy_set_header X-Original-URI $request_uri;\n"
                "}"
            ),
            docs_url=f"{D}/http/ngx_http_auth_jwt_module.html",
        ),
    ),

    Feature(
        key="_plus_queue",
        label="Request queueing",
        category="proxy",
        edition="plus",
        contexts=(),
        type="bool",
        oss_alternative=(
            "There is no queue in the free version.  When every backend is at its "
            "connection limit the request gets a 502 instead of waiting.  The practical "
            "answer is to set max_conns high enough that you do not hit it, and use rate "
            "limiting to shape the load before it gets there."
        ),
        help=HelpText(
            summary="Hold requests in a queue when every backend is busy, instead of failing them.",
            detail=(
                "Paid feature.  Smooths out short spikes by making requests wait a moment "
                "rather than rejecting them."
            ),
            use_cases=["Traffic that comes in short sharp bursts"],
            example_config="# free version, shape the load before it arrives\nlimit_req zone=api burst=50 nodelay;",
            docs_url=f"{D}/http/ngx_http_upstream_module.html#queue",
        ),
    ),
)
