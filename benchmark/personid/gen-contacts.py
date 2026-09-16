#!/usr/bin/env python3
"""Generate a JSON Lines contact file for `sunder import` measurements.

Every row carries a unique e-mail and a unique phone, so an -offline import
inserts exactly N persons and 3N tokens (email, phone, name) with the
derived indexes off. Names repeat on purpose - they do in real data, and the
name token is deliberately non-unique. The seed makes a file reproducible,
so two variants import byte-identical input.

usage: gen-contacts.py N SEED > contacts.jsonl
"""
import json
import random
import sys

FIRST = ["Ana", "Ivan", "Marija", "Josip", "Petra", "Luka", "Iva", "Marko",
         "Katarina", "Filip", "Sara", "Tomislav", "Lucija", "Nikola", "Ema",
         "Matej", "Jelena", "Ante", "Maja", "Karlo"]
LAST = ["Horvat", "Kovačević", "Babić", "Marić", "Jurić", "Novak", "Kovačić",
        "Knežević", "Vuković", "Marković", "Petrović", "Matić", "Tomić",
        "Pavlović", "Kovač", "Božić", "Blažević", "Grgić", "Pavić", "Radić"]


def main() -> None:
    n = int(sys.argv[1])
    rnd = random.Random(int(sys.argv[2]))
    out = sys.stdout
    # A random permutation of the identifier space, so file order carries no
    # locality of its own - the import sorts each batch by token anyway, and
    # the token is a keyed HMAC, but the fixture must not smuggle order in.
    for i in rnd.sample(range(n), n):
        row = {
            "email": f"c{i}@bench.example",
            "phone": f"+3859{i:08d}"[:13] if i < 10**8 else f"+385{i:09d}",
            "name": f"{rnd.choice(FIRST)} {rnd.choice(LAST)}",
        }
        out.write(json.dumps(row, ensure_ascii=False))
        out.write("\n")


if __name__ == "__main__":
    main()
