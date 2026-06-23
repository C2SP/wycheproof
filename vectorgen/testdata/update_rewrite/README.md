# update_rewrite

Self-contained fixture for `TestUpdateRewritesExistingValueWithOverwrite`.
Exercises `vectorgen.Update` with `Overwrite: true` replacing an existing
field value — the "generator-bug rewrite" use case from the design doc.

- `before.json` — a minimal two-test file with a `value` field set to
  `"before"` on each test.
- `rewrite_schema.json` — a minimal schema permitting the file's shape. Used
  to isolate this test from schema specifics of real algorithms.
