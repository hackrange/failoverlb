# The user guide

The manual is generated, not typed.  Chapters are Python files that call a
small set of helpers, and the build turns them into a Word document with a
working table of contents.

Keeping the words apart from the layout is what makes the manual survive.  A
feature changes, its chapter changes, and the whole book is rebuilt with the
numbering and the contents worked out again.

## Building it

    docker build -t nfm-docs docs/
    docker run --rm -v "$PWD/docs:/docs" nfm-docs python /docs/build.py

That writes `docs/NGINX-Management-User-Guide.docx`.

Open it in Word once and let the table of contents populate.  The field is set
to refresh on open, so most readers never see the placeholder line.

## Taking the screenshots

Every picture is of a real running system.  Point the capture at a node you can
sign in to:

    docker run --rm -v "$PWD/docs:/docs" \
      -e NFM_URL=https://your-node/lb \
      -e NFM_USER=docs -e NFM_PASSWORD=... -e NFM_TOTP=... \
      nfm-docs python /docs/capture.py

The account needs an authenticator enrolled, because local accounts must have
one and a script cannot skip that.  `NFM_TOTP` is its base32 secret.

Hostnames are rewritten in the browser before each shot, so the pictures are of
the real thing while reading as the example domain.  Set that up in
`docsconf.py`, or pass `NFM_DOCS_SUBS` as a json list of pairs.

Some screens are captured by their own script rather than the general sweep,
because they are only worth photographing with something on them:

| Script | Why it is separate |
|---|---|
| `shot-changes.py` | Empty unless something is saved and not applied |
| `shot-import.py`  | Needs a config pasted in to show a preview |
| `shot-zones.py`   | Four tabs, and empty until there is one of each |
| `shot-dialogs.py` | Every dialog, opened by clicking rather than by address |
| `shot-account.py` | First time setup, which only happens once per account |
| `shot-last2.py`   | Two dialogs the sweep cannot reach |

Anything one of these creates, it removes again.

## Checking it

    docker run --rm -v "$PWD/docs:/docs" nfm-docs python /docs/checkstyle.py

It fails the build on an em dash, a sentence gap with one space instead of two,
a reference to AI, a chapter number out of sequence, an appendix that has
drifted out of the back matter, or any hostname you have said must not appear.
Set `NFM_DOCS_FORBIDDEN` to a json list of patterns for the last one.

It also reports any screenshot that is not used in a chapter yet, which is how
you find the screens nobody has written about.

## House style

Two spaces between sentences.  No em dashes.  Plain words, and never assume the
reader has done this before.  A term that has to be jargon is explained in
ordinary language the first time it appears and again in the glossary.

## What is not in git

The screenshots, the annotated copies, and the finished document.  They are all
rebuilt from a running system, they are large, and they change wholesale on
every build.
