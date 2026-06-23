# add_pr255

Fixture for `TestAddRecreatesPR255`, and the worked example for the "A Whole
New File" workflow in `doc/vectorgen.md`. Recreates the new vector file added
by [PR #255](https://github.com/C2SP/wycheproof/pull/255) (no `before.json` —
the target does not exist).

- `envelope.json` — the entire file metadata bundled with the test data:
  algorithm, schema, header, groupTemplate, tests (tcIds stripped), notes.
- `after.json` — the file at commit
  [`1812c93`](https://github.com/C2SP/wycheproof/commit/1812c93fea09a7c7eb385ffd0ff41ae63514918d)
  from PR #255. Asserted byte-equal to the output of `vectorgen.Add`.

This fixture uses the embedded `mldsa_verify_schema.json` from
`wycheproof.Schemas` (no local schema copy needed; the schema is unchanged
between the embedded snapshot and the PR).

Replay from the repo root:

```
rm -f /tmp/mldsa_87_reduction_omission_verify_test.json
GOEXPERIMENT=jsonv2 go run ./tools/vectorgen add --create \
  --vectors /tmp/mldsa_87_reduction_omission_verify_test.json \
  --input vectorgen/testdata/add_pr255/envelope.json
diff /tmp/mldsa_87_reduction_omission_verify_test.json vectorgen/testdata/add_pr255/after.json
```
