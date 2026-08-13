"""
Part 7: bringing an existing nginx across.

House style: two spaces between sentences, no em dashes, plain words.
"""


def write(b, shot, term):
    _import(b, shot, term)


def _import(b, shot, term):
    b.h1("31. Importing an existing nginx config")

    b.para(
        "If you already run nginx, you do not have to type all of it in again.  "
        "The Import page reads your existing configuration and turns it into "
        "sites and pools here.  This is usually the first thing somebody does, "
        "so it is worth doing carefully.")

    b.h2("Nothing happens until you say so")
    b.para(
        "The important thing about this page is how safe it is.  Pasting a "
        "configuration in and pressing the preview button writes nothing at "
        "all.  It reads your text, works out what it would make, and shows "
        "you.  You can point it at your live configuration purely to see what "
        "this software makes of it, and walk away.")

    b.para(
        "Even after you import, nothing is live.  Everything arrives switched "
        "off and unapplied, so you can look it over, fix anything that came "
        "across oddly, and only then turn it on.")

    b.picture(shot("import"), "The Import page, waiting for a config.")

    b.h2("Which file to paste")
    b.warn(
        "Paste the file your sites are actually in.  A top level nginx.conf is "
        "usually just a list of includes, so pasting that shows you almost "
        "nothing and looks like the import is broken.  On most systems the "
        "sites live in sites-enabled or conf.d.")

    b.para(
        "If your configuration is split across several files, paste them one "
        "after another into the same box, or import them one at a time.  Order "
        "does not matter.")

    b.code([
        "$ cat /etc/nginx/sites-enabled/*",
    ], "One way to get everything on screen at once, ready to copy.")

    b.h2("Reading the preview")
    b.para(
        "Press See what it would make.  The page splits what it found into "
        "three parts.")

    b.picture(shot("import-preview"),
              "A preview.  Everything shown here would be created, and nothing "
              "has been yet.")

    b.table(
        ["Section", "What it holds"],
        [
            ["Pools",
             "Every upstream block, with its servers.  Settings such as backup "
             "and weight come across with them."],
            ["Sites",
             "Every server block, with its names, ports, whether it uses "
             "https, and its paths.  Under each one is a plain list of what "
             "was done and why."],
            ["Left alone",
             "Anything that could not be turned into a setting on these "
             "screens.  This section is the one to read properly."],
        ],
        widths=[1.2, 5.1])

    b.para(
        "Each entry has a tick box.  Untick anything you do not want.  A common "
        "reason is an old site you have been meaning to retire, and the import "
        "is a good moment to not bring it with you.")

    b.h2("What the notes under a site mean")
    b.para(
        "The lines under each site say what the importer decided.  They are "
        "worth reading because they explain things you would otherwise notice "
        "later and find confusing.")

    b.table(
        ["A note like this", "Means"],
        [
            ["The plain http block only redirected to https, so it became the "
             "force https switch",
             "You had two server blocks for one name, one of which only "
             "forwarded to the other.  That is one site here with a switch "
             "turned on, not two sites."],
            ["Paths were brought over, so each keeps its own backend",
             "Your location blocks became paths on the site, as in Chapter "
             "10."],
            ["Some directives had no setting here, so they were kept as custom "
             "config",
             "Anything without a box on the screen is preserved as raw "
             "configuration on the site rather than dropped."],
            ["No certificate was attached",
             "See the next section.  This one always happens and it is not an "
             "error."],
        ],
        widths=[2.9, 3.4])

    b.h2("Certificates are never brought across")
    b.para(
        "Your configuration names certificate files by path.  Those paths point "
        "at files on the machine the configuration came from, which is not "
        "necessarily a machine this software manages, and the private keys are "
        "not in the text you pasted anyway.")

    b.para(
        "So a site comes across knowing it uses https and with no certificate "
        "chosen.  After importing, go to Certificates and either get a new one "
        "from Lets Encrypt, which is usually easiest, or upload the existing "
        "certificate and key.  Then open the site, choose it, and apply.  "
        "Chapter 11 covers both.")

    b.h2("Warnings you may see")
    b.table(
        ["Warning", "What to do"],
        [
            ["Looks like a proxy but no backend could be worked out",
             "The site is created with nothing behind it.  This happens when "
             "the proxying is inside the paths rather than on the server "
             "itself, which is fine: check the paths have their pools, and "
             "leave the site's own backend empty."],
            ["A name is already used by an existing site",
             "Two sites answering for the same name is a problem, so the "
             "import will not quietly make one.  Rename or untick."],
            ["An upstream was referred to but never defined",
             "Your configuration pointed at a pool that was declared in a file "
             "you did not paste.  Paste that file too and preview again."],
        ],
        widths=[2.4, 3.9])

    b.h2("What is deliberately not imported")
    b.para(
        "Some things are left behind on purpose rather than because they could "
        "not be read.")

    b.bullets([
        "Anything to do with how nginx itself is built or started, since this "
        "software manages that separately through the nginx Build page.",
        "Log formats and file paths, because logs are handled per node here.",
        "Certificate and key files, as above.",
    ])

    b.note(
        "Anything genuinely not understood is listed in Left alone with the "
        "reason.  Nothing is dropped silently.  That is the point of that "
        "section, and it is why it is worth reading rather than skipping to "
        "the import button.")

    b.h2("Doing the import")
    b.steps([
        "Untick anything you do not want.",
        "Press Import the ticked ones.",
        "Go to Backend Pools and check the servers are right.  Give the pools "
        "better names now if the originals were cryptic, because renaming later "
        "means updating whatever points at them.",
        "Go to Sites and open each one.  Check the names, the mode, and the "
        "paths.",
        "Sort out certificates, as above.",
        "Turn each site on when you are happy with it.",
        "Press Apply config.",
    ])

    b.warn(
        "Do not import and apply in one go on a busy day.  The import brings "
        "everything across switched off precisely so you can read it first.  "
        "Applying immediately gives up that safety for no gain.")

    b.h2("A worked example")
    b.para(
        "The preview above came from this configuration, which is a small but "
        "realistic one: two pools, a plain http block that only forwards to "
        "https, and a secure block with two paths going to different places.")

    b.code([
        "upstream shop_web {",
        "    server 192.0.2.11:8080;",
        "    server 192.0.2.12:8080;",
        "}",
        "",
        "server {",
        "    listen 80;",
        "    server_name shop.domain.com;",
        "    return 301 https://$host$request_uri;",
        "}",
        "",
        "server {",
        "    listen 443 ssl http2;",
        "    server_name shop.domain.com;",
        "    ssl_certificate /etc/ssl/certs/shop.crt;",
        "",
        "    location / {",
        "        proxy_pass http://shop_web;",
        "    }",
        "    location /api {",
        "        proxy_pass http://shop_api;",
        "    }",
        "}",
    ])

    b.para(
        "The preview turned that into two pools and one site.  Notice what it "
        "did with the two server blocks: they became a single site with force "
        "https turned on, rather than two sites, because the first one existed "
        "only to send people to the second.  The two locations became two "
        "paths, each keeping its own pool.  No certificate was attached, and "
        "the note says so.")

    b.para(
        "That is the shape of nearly every import.  Read the notes, fix the "
        "certificate, check the pools, then turn it on.")
    b.page_break()
