# add_pr254c2

Fixture for `TestAddRecreatesPR254Commit2`, and the worked example for the
"A New Group in an Existing File" workflow in `doc/vectorgen.md`. Recreates
the second commit of [PR #254](https://github.com/C2SP/wycheproof/pull/254)
(re-encryption test vectors appended to
`mlkem_512_semi_expanded_decaps_test.json`).

- `before.json` — the file at commit [`f0b4b70`] (post-ek/K, 7 tests, no
  re-encryption group yet).
- `envelope.json` — distilled from commit [`44dcf46`]'s diff: the new group's
  template, its two tests (with tcIds stripped), and the new
  `MalleableCiphertext` notes entry.
- `after.json` — the file at commit [`44dcf46`]. Asserted byte-equal to the
  output of `vectorgen.Add(before, envelope)`.
- `mlkem_semi_expanded_decaps_test_schema.json`, `common.json` — schemas at
  commit [`f0b4b70`], needed because the embedded schemas in `wycheproof`
  predate the `ek`/`K` additions.

Replay from the repo root:

```
cp vectorgen/testdata/add_pr254c2/before.json /tmp/mlkem_512.json
GOEXPERIMENT=jsonv2 go run ./tools/vectorgen add \
  --vectors /tmp/mlkem_512.json \
  --input vectorgen/testdata/add_pr254c2/envelope.json \
  --schemas-dir vectorgen/testdata/add_pr254c2
diff /tmp/mlkem_512.json vectorgen/testdata/add_pr254c2/after.json
```

[`f0b4b70`]: https://github.com/C2SP/wycheproof/commit/f0b4b70e5bca133a9afe3f725af87922ee900bd9
[`44dcf46`]: https://github.com/C2SP/wycheproof/commit/44dcf469edba24279ff29c2875d27313075296d1
