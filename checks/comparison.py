"""
Whether the feature comparison holds together, and whether it is still honest.

The page is a table of judgements, so most of it cannot be tested: no check can
tell you whether HAProxy ALOHA deserves four stars for post quantum key
exchange.  What a check can do is stop the two ways this page actually breaks.

The first is mechanical.  Four products means four scores per row, and a row
missing one is a KeyError on a page somebody reached from the menu.  That is a
500 caused by a typo in a data file, which is the cheapest possible bug to
prevent and an embarrassing one to ship.

The second is the one worth having.  A comparison written by one of the four
products drifts toward its author, and it does not drift by anybody deciding
to lie.  It drifts by a row quietly getting a fifth star, by the losing rows
getting shorter notes than the winning ones, and by the totals being mentioned
only while they flatter.  So this also asserts the shape of the honesty: that
we do not win everywhere, that the rows we lose are argued as carefully as the
rows we win, and that the tally the page prints is the tally the data supports.

None of that proves the scores are right.  It proves nobody has quietly turned
the page into a brochure.

    docker exec -i nginx-fleet-manager python < checks/comparison.py
"""
import sys

from app.catalog.comparison import (
    CAPABILITIES,
    CATEGORIES,
    PRICING,
    PRODUCTS,
    RIVAL_KEYS,
    by_category,
    only_here,
    pricing,
    product_totals,
    totals,
)

results = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"    {'pass' if ok else 'FAIL'}  {name}")
    if not ok and detail:
        print(f"          {detail}")


keys = [p["key"] for p in PRODUCTS]

print()
print("  every row is complete")

missing = [f"{c['key']}.{k}" for c in CAPABILITIES for k in keys if k not in c]
check("every row scores every product", not missing,
      f"a page hit would be a KeyError on: {missing[:6]}")

bad = [f"{c['key']}.{k}={c.get(k)}" for c in CAPABILITIES for k in keys
       if not isinstance(c.get(k), int) or not 0 <= c.get(k, -1) <= 5]
check("every score is a whole number from 0 to 5", not bad,
      f"off the scale: {bad[:6]}")

no_note = [c["key"] for c in CAPABILITIES
           if not c.get("note", "").strip() or not c.get("others", "").strip()]
check("every row argues both halves", not no_note,
      f"a score with no reasoning is an assertion: {no_note}")

dupes = [k for k in {c["key"] for c in CAPABILITIES}
         if [c["key"] for c in CAPABILITIES].count(k) > 1]
check("row ids are unique", not dupes,
      f"two rows share an id, so an anchor link lands on the wrong one: {dupes}")

orphans = sorted({c["category"] for c in CAPABILITIES} - set(CATEGORIES))
check("every row lands in a category the page renders", not orphans,
      f"these rows exist and are invisible: {orphans}")

grouped = sum(len(rows) for _, rows in by_category())
check("no row is dropped between the data and the page",
      grouped == len(CAPABILITIES),
      f"{len(CAPABILITIES)} rows in, {grouped} rows out")


print()
print("  the page has what it needs to draw")

annotated = [r for _, rows in by_category() for r in rows]
check("every row carries the two derived numbers",
      all("rivals_best" in r and "row_best" in r for r in annotated),
      "the template reads these, so a missing one is a 500")

check("row_best really is the best in the row",
      all(r["row_best"] == max(r[k] for k in keys) for r in annotated),
      "the wrong cell would be highlighted as the leader")

check("rivals_best excludes us",
      all(r["rivals_best"] == max(r[k] for k in RIVAL_KEYS) for r in annotated),
      "we would be compared against ourselves and never read as behind")

scores = product_totals()
check("every product is scored once", len(scores) == len(PRODUCTS),
      f"{len(scores)} cards for {len(PRODUCTS)} products")

check("the totals are sorted highest first",
      [s["total"] for s in scores] == sorted((s["total"] for s in scores),
                                             reverse=True),
      f"order was {[(s['label'], s['total']) for s in scores]}")

check("the ranks match the order",
      [s["rank"] for s in scores] == list(range(1, len(scores) + 1)))

check("no total can exceed the ceiling",
      all(0 <= s["total"] <= s["ceiling"] for s in scores),
      f"{[(s['label'], s['total'], s['ceiling']) for s in scores]}")


print()
print("  the pricing section is dated and complete")

check("every product has a price card", len(pricing()) == len(PRODUCTS),
      "a missing card reads as a product that is free")

check("the price cards follow the same order as the totals",
      [p["key"] for p in pricing()] == [s["key"] for s in scores],
      "two orderings on one page is how a reader loses the thread")

undated = totals().get("pulled", "").strip()
check("the pricing carries a date", bool(undated),
      "a cost with no date on it looks current forever")

check("every price card says where the number came from",
      all(p.get("sources", "").strip() for p in PRICING),
      "two of these vendors publish nothing, so the source is the caveat")

ours = next(p for p in PRICING if p["key"] == "lb")
check("our own price is stated as zero", "$0" in ours["headline"],
      f"headline was {ours['headline']!r}")

check("the free column still admits the cost is not zero",
      any(w in ours["detail"].lower() for w in ("carry", "on call", "you")),
      "a free licence is not a free product, and the card has to say so")


print()
print("  the page has not turned into a brochure")

losing = [c for c in CAPABILITIES if c["lb"] < max(c[k] for k in RIVAL_KEYS)]
winning = [c for c in CAPABILITIES if c["lb"] > max(c[k] for k in RIVAL_KEYS)]

check("we do not win every row", bool(losing),
      "a comparison where the author wins everything is marketing")

check("we do not lose every row", bool(winning),
      "if this ever fires, the honest move is to stop shipping the page")

check("we are not first on the star total", not scores[0].get("us"),
      "we may genuinely lead one day, and then this check needs a human "
      "reading it rather than a quiet edit")

perfect = [c["key"] for c in CAPABILITIES if c["lb"] == 5 and
           all(c[k] < 5 for k in RIVAL_KEYS)]
check("clean sweeps are rare enough to be arguments, not habits",
      len(perfect) <= len(CAPABILITIES) // 3,
      f"{len(perfect)} rows give us five and nobody else: {perfect}")

lose_words = sum(len(c["note"].split()) + len(c["others"].split())
                 for c in losing) / max(len(losing), 1)
win_words = sum(len(c["note"].split()) + len(c["others"].split())
                for c in winning) / max(len(winning), 1)
check("the rows we lose are argued as carefully as the rows we win",
      lose_words >= win_words * 0.5,
      f"{lose_words:.0f} words on average where we lose against "
      f"{win_words:.0f} where we win, which is how a table stops being read")

t = totals()
check("the printed tally matches the data",
      t["ahead"] == len(winning) and t["behind"] == len(losing)
      and t["ahead"] + t["behind"] + t["level"] == t["total"],
      f"page would print {t} against {len(winning)} won, {len(losing)} lost")

for c in only_here():
    check(f"only here: {c['key']} really is nowhere else",
          all(c[k] == 0 for k in RIVAL_KEYS),
          "the strongest claim on the page, so it gets the strictest test")

# A 1 means two different things: "possible, but you are building it yourself"
# and "we could find nothing published either way".  Both are honest, the star
# cannot tell them apart, and only the second is a claim about somebody else's
# product that we have not evidenced.  So the rows that mean the second say so
# in the data, and these two checks keep the marker and the words together.
marked = [(c["key"], k) for c in CAPABILITIES
          for k in c.get("unconfirmed", []) if c[k] != 1]
check("anything marked unconfirmed scores exactly one star", not marked,
      f"a score other than 1 is a claim we said we could not make: {marked}")

silent = [c["key"] for c in CAPABILITIES if c.get("unconfirmed")
          and "confirm" not in c["others"].lower()
          and "could find nothing" not in c["others"].lower()]
check("an unconfirmed row says so in the note the reader sees", not silent,
      f"the marker is in the data and not on the page, which helps nobody: "
      f"{silent}")

check("we have not marked our own column unconfirmed",
      not any("lb" in c.get("unconfirmed", []) for c in CAPABILITIES),
      "not knowing what our own product does is a different problem")


print()
failed = [name for name, ok, _ in results if not ok]
print(f"  {len(results) - len(failed)} of {len(results)} passed")
print()
print("  what this does not cover:")
print("    - whether any individual score is correct, which needs a person")
print("    - whether the vendors have shipped something since the scores were")
print(f"      taken, which was {totals()['pulled']}")
print("    - whether the prices are current, which they will not be for long")
print()
print("  RESULT:", "the comparison holds up" if not failed
      else f"{len(failed)} PROBLEMS: {failed}")
sys.exit(1 if failed else 0)
