# update_pr254c1

Fixture for `TestUpdateAddsFields`, and the worked example for the "Add or
Rewrite a Field of Existing Vectors" workflow in `doc/vectorgen.md`.
Recreates the *contents* added by the first commit of
[PR #254](https://github.com/C2SP/wycheproof/pull/254): the `ek` field on
every test plus the `K` field on tcId 1.

- `before.json` — the file at commit [`7c661e3`] (no ek/K).
- `envelope.json` — the patches: tcId-keyed entries supplying `ek` (and `K`
  for tcId 1), extracted from commit [`f0b4b70`].
- `after.json` — captured from `vectorgen.Update`'s output on first run.
  Asserted byte-equal on subsequent runs. The key order is per the schema's
  `properties` declaration (`tcId, comment, dk, ek, c, K, result, flags`),
  which differs slightly from the human-authored order in commit [`f0b4b70`]
  (which places `ek` after `c`). The values are identical.
- `mlkem_semi_expanded_decaps_test_schema.json`, `common.json` — schemas at
  commit [`f0b4b70`], needed because the embedded schemas predate the
  `ek`/`K` additions.

Replay from the repo root:

```
cp vectorgen/testdata/update_pr254c1/before.json /tmp/mlkem_512.json
GOEXPERIMENT=jsonv2 go run ./tools/vectorgen update \
  --vectors /tmp/mlkem_512.json \
  --input vectorgen/testdata/update_pr254c1/envelope.json \
  --schemas-dir vectorgen/testdata/update_pr254c1
diff /tmp/mlkem_512.json vectorgen/testdata/update_pr254c1/after.json
```

[`7c661e3`]: https://github.com/C2SP/wycheproof/commit/7c661e3a5379b65645e4f8dab44d0ba88b20906e
[`f0b4b70`]: https://github.com/C2SP/wycheproof/commit/f0b4b70e5bca133a9afe3f725af87922ee900bd9
