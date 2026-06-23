# add_intogroup

Fixture for `TestAddIntoGroup`, and the worked example for the "New Tests in
an Existing Group" workflow in `doc/vectorgen.md`: a single test appended to
an existing group identified by its `source.name`, without creating a new
group. Real instances of this workflow: commits [`d97bd47f`] and
[`b7e3f4a7b`] each appended one test into an existing ML-DSA verify group.

- `before.json` — the file at commit [`44dcf46`] (i.e. the
  post-[PR #254](https://github.com/C2SP/wycheproof/pull/254) state, with the
  re-encryption group already present).
- `envelope.json` — one synthetic test (values copied from an existing entry
  so schema validation passes), no `tcId`.
- `after.json` — captured output; the appended test becomes tcId 10. Asserted
  byte-equal by the test.
- `mlkem_semi_expanded_decaps_test_schema.json`, `common.json` — schemas
  matching the post-PR-#254 state (the `ek`/`K` field additions are not in
  the embedded schemas).

Replay from the repo root:

```
cp vectorgen/testdata/add_intogroup/before.json /tmp/mlkem_512.json
GOEXPERIMENT=jsonv2 go run ./tools/vectorgen add \
  --vectors /tmp/mlkem_512.json \
  --input vectorgen/testdata/add_intogroup/envelope.json \
  --into-group github/lukaszobernig/reenc \
  --schemas-dir vectorgen/testdata/add_intogroup
diff /tmp/mlkem_512.json vectorgen/testdata/add_intogroup/after.json
```

[`d97bd47f`]: https://github.com/C2SP/wycheproof/commit/d97bd47feb6363c9f87e23413d371a9b79754358
[`b7e3f4a7b`]: https://github.com/C2SP/wycheproof/commit/b7e3f4a7b492ec53e2e2e54fc1507617d8c6d0f0
[`44dcf46`]: https://github.com/C2SP/wycheproof/commit/44dcf469edba24279ff29c2875d27313075296d1
