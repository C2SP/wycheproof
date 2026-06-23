# replace_reenc

Fixture for `TestReplacePreservesGroupPosition`, and the worked example for
the "Replace a Whole Group of Vectors" workflow in `doc/vectorgen.md` (the
doc's envelope example is this exact scenario). The
[PR #254](https://github.com/C2SP/wycheproof/pull/254) re-encryption group
(`github/lukaszobernig/reenc@1.0`, 2 tests) is swapped for a regenerated
`2.0` group with a single test.

A real instance of this situation: commit [`2abbf88`] removed invalid hint
limit vectors from a group in the ML-DSA sign_seed files (5 tests down to 2).
That commit predates vectorgen and kept the old tcIds; `replace` instead
renumbers every test in the file densely from 1.

- `envelope.json` — the replacement group's template (`source` version bumped
  to `2.0`) and its single test.
- `after.json` — captured output. The replacement group sits at the original
  group's position (second, after aws-lc), all tests are renumbered from 1,
  and `numberOfTests` reflects the smaller group. Asserted byte-equal by the
  test.

The starting file and schemas are shared with the sibling fixture:
`add_intogroup/before.json` (the post-PR-#254 state, commit [`44dcf46`]) and
its schema copies.

Replay from the repo root:

```
cp vectorgen/testdata/add_intogroup/before.json /tmp/mlkem_512.json
GOEXPERIMENT=jsonv2 go run ./tools/vectorgen replace \
  --vectors /tmp/mlkem_512.json \
  --source github/lukaszobernig/reenc@1.0 \
  --input vectorgen/testdata/replace_reenc/envelope.json \
  --schemas-dir vectorgen/testdata/add_intogroup
diff /tmp/mlkem_512.json vectorgen/testdata/replace_reenc/after.json
```

[`2abbf88`]: https://github.com/C2SP/wycheproof/commit/2abbf8892a895cc2ef878a8cff474d1963d071ff
[`44dcf46`]: https://github.com/C2SP/wycheproof/commit/44dcf469edba24279ff29c2875d27313075296d1
