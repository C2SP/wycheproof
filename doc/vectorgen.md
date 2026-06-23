# Adding and Updating Wycheproof Vectors

Wycheproof offers a tool called `vectorgen` to help contributors add, update or
replace test cases.

To use `vectorgen` you'll need [Go 1.26+](https://go.dev/doc/install).

Three common workflows are covered:

1. **add**ing new vectors: a whole new file, a new group in an existing file,
   or new tests in an existing group,
2. **update**ing existing vectors to add or rewrite a field,
3. **replace**ing a whole group of vectors with regenerated output.

Until Go 1.27 is released `vectorgen` requires setting `GOEXPERIMENT=jsonv2`
once per shell env, or as an env variable prefix before every tool invocation.

> [!IMPORTANT]
> If you see a build error like
>
> ```
> imports encoding/json/jsontext: build constraints exclude all Go files in
> .../src/encoding/json/jsontext
> ```
>
> it means `GOEXPERIMENT=jsonv2` is not set in the environment.

After any change, run `go run ./tools/vectorgen fmt --check
'testvectors_v1/*.json'` and `go run ./tools/vectorgen lint` to confirm the
result is canonical and schema-valid. These checks are also
[applied in CI][schema lint] for every pull request.

## Workflow

`vectorgen` operations are driven by an **envelope**: a small JSON document
describing only your change. E.g. the tests to add, optionally a new group's
template and notes.

The workflow is always the same: build an envelope (scaffolded from the
schema, or written by hand), fill in the values from your generator's output,
and apply it with a `vectorgen` subcommand.

The tool merges the envelope into the target vector file and handles
the mechanical parts: `tcId` assignment, `numberOfTests`, canonical formatting,
and schema validation.

## Adding New Vectors

All three variants use the same envelope shape and the `vectorgen add`
subcommand. Two rules apply throughout:

* Do NOT include `tcId` fields in tests. The tool assigns them; supplying one
  is an error.
* The tool preserves the key order of the test objects you supply. When adding
  to an existing file, match that file's key order. Scaffold output follows
  the schema's order, which may differ.

### A Whole New File

Use case: you're adding brand new coverage for an algorithm. You either created
a schema, or are repurposing an existing one, and want to create a new `.json`
file with your vectors.

Worked example: [`vectorgen/testdata/add_pr255/`](../vectorgen/testdata/add_pr255/README.md)
recreates PR #255's new ML-DSA vector file from its envelope.

1. **Scaffold a starter envelope** for the schema:

   ```
   go run ./tools/vectorgen scaffold add \
     --schema mlkem_semi_expanded_decaps_test_schema.json \
     --output envelope.json
   ```

   The output has placeholders like `"<HexBytes>"` and `"<one of: valid,
   invalid, acceptable>"` so it's obvious what each field expects.

2. **Edit `envelope.json`**: fill in `algorithm` and `header`, the
   `groupTemplate` (the new group's object, minus its `tests` array), the
   `tests`, and any `notes`.

3. **Apply with `--create`**:

   ```
   go run ./tools/vectorgen add --create \
     --vectors testvectors_v1/my_new_test.json \
     --input envelope.json
   ```

### A New Group in an Existing File

Use case: your vectors belong in an existing file but need a group of their
own: a new source, a new key, or different group-level parameters.

Worked example: [`vectorgen/testdata/add_pr254c2/`](../vectorgen/testdata/add_pr254c2/README.md)
recreates PR #254's re-encryption group append.

Scaffold and edit as above, but remove the `algorithm`, `schema`, and `header`
fields (those are only for new files). Keep `groupTemplate`, `tests`, and
optionally `notes`. Apply without `--create`:

```
go run ./tools/vectorgen add \
  --vectors testvectors_v1/mlkem_512_semi_expanded_decaps_test.json \
  --input envelope.json
```

The new group is appended to `testGroups` and its tests numbered continuing
from the file's last tcId. Appending a group identical (ignoring tcIds) to an
existing one is an error, so re-running a generator won't silently duplicate
its group. Use `--into-group` or `replace` to modify an existing group.

### New Tests in an Existing Group

Use case: you've generated new test cases that fit an existing test group
(same source name), and want to append them.

Worked example: [`vectorgen/testdata/add_intogroup/`](../vectorgen/testdata/add_intogroup/README.md)
appends one test into PR #254's re-encryption group.

Scaffold and edit as above, keeping only `tests` and optionally `notes`. Apply
with `--into-group`, naming the group's source:

```
go run ./tools/vectorgen add \
  --vectors testvectors_v1/mlkem_512_semi_expanded_decaps_test.json \
  --input envelope.json \
  --into-group github/aws/aws-lc
```

The tool finds the matching group, appends your tests with continuing tcIds,
recomputes `numberOfTests`, and merges new note entries. If more than one
group shares the source name, disambiguate with `name@version`.

## Add or Rewrite a Field of Existing Vectors

Use case: a generator was updated to produce a new field (e.g. `ek`), or a
bug was fixed and existing values need rewriting.

Worked example: [`vectorgen/testdata/update_pr254c1/`](../vectorgen/testdata/update_pr254c1/README.md)
recreates PR #254's `ek`/`K` field additions.

1. **Scaffold an update envelope by hand** — there's no `scaffold update`
   today. The shape is small:

   ```json
   {
     "source": "github/aws/aws-lc",
     "patches": [
       { "tcId": 1, "ek": "...", "K": "..." },
       { "tcId": 2, "ek": "..." }
     ]
   }
   ```

   `source` selects which groups to patch (use `"name@version"` to
   disambiguate). Each patch's `tcId` identifies the test; other fields are
   merged in.

2. **Apply** (use globs to patch parallel files in one shot):

   ```
   go run ./tools/vectorgen update \
     --vectors 'testvectors_v1/mlkem_*_semi_expanded_decaps_test.json' \
     --input envelope.json
   ```

   Defaults are strict:
   - **All matching tests must be covered.** Add `--partial` to permit a
     subset.
   - **Existing field values must not differ.** Add `--overwrite` to rewrite
     a field that already has a different value.

   New keys are inserted at the position implied by the test-vector schema's
   `properties` array. Existing key order is preserved.

## Replace a Whole Group of Vectors

Use case: a generator bug forced you to regenerate every test in a group, or
a group's tests have changed in size and composition.

Worked example: [`vectorgen/testdata/replace_reenc/`](../vectorgen/testdata/replace_reenc/README.md)
swaps the PR #254 re-encryption group for a regenerated one.

1. **Construct an envelope** with the new group's template and tests (same
   shape as the add envelope; no `algorithm`/`schema`/`header`):

   ```json
   {
     "groupTemplate": {
       "type": "MLKEMDecapsValidationTest",
       "source": { "name": "github/lukaszobernig/reenc", "version": "2.0" },
       "parameterSet": "ML-KEM-512"
     },
     "tests": [
       { "comment": "...", "dk": "...", "c": "...", "ek": "...", "result": "invalid", "flags": [...] }
     ]
   }
   ```

2. **Apply with `--source`** identifying the group to swap out:

   ```
   go run ./tools/vectorgen replace \
     --vectors testvectors_v1/mlkem_512_semi_expanded_decaps_test.json \
     --source github/lukaszobernig/reenc@1.0 \
     --input envelope.json
   ```

   The new group lands at the position of the old one (not appended at the
   end). Every test in the file is renumbered sequentially from 1, since the
   replacement may differ in size.

If `--source` matches more than one group, you'll get an error listing them
— disambiguate with `name@version`.

## Safety Net

Every mutating operation (`add`, `update`, `replace`) validates the merged
result against the schema before writing. On failure, the candidate output
is written to `<vectorfile>.rej` and the original is left untouched, so
you can inspect what went wrong without losing the original file.

## Schema Best Practices

All new test types should be accompanied by [JSON schema] files describing the
test vector data structure. See the [`schemas/` directory][schema dir] for
existing examples.

All new schema files should:

* Describe common top-level properties matching pre-existing schemas/vectors
  (e.g. `algorithm`, `header`, `notes`, `numberOfTests`, and `schema`).
* Divide vector files into test groups.
* Use `"additionalProperties": false` in each defined object to prevent
  unspecified fields in vector data.
* Use `"required": [...]` in each defined object to specify the expected
  mandatory properties in vector data.
* Within each test group, specify a `source`, referencing the common
  [`common.json#/definitions/Source`][source schema] element.
* Avoid deprecated schema fields (e.g. `generatorVersion`).
* Avoid duplicating complex schema elements across many schema files (e.g.
  public key definitions). Instead, create a separate schema file for the common
  object and [reference it][schema ref] throughout other schema files.

## Test Vector Best Practices

All new JSON test vector files should:

* Reference a schema.
* Be placed in the `testvectors_v1/` directory.
* Be divided up by test type, and important algorithm parameters
  (e.g. encap vs decap, key size).
  When convenient, try to split the test vectors so that consumers
  that may not support all variations of the algorithm can test with specific
  vector files without needing additional post-filtering.
  While the schema may indicate test groups can contain multiple test types
  we've come to prefer one test file per test group type.

## Choosing a Source Name

The common [source schema] allows specifying a name and version for your new
test vectors.

We intend to use the source element to allow targeted updates to test vector
data identified by the source name/version. For this reason, when augmenting
existing vector files with new data try to choose a source name that will be
specific enough for future regeneration without affecting unrelated data.

For example, using source name "github/myusername/weak_params" for new vector
data added to `imaginary_algorithm_2048_test.json` may be preferable to
"github.com/myusername" if you intend to add other kinds of test vectors to
`imaginary_algorithm_2048_test.json` in the future, and would want to be able to
update those separately from the weak parameter test vector data.

## Appendix: Programmatic Updates with Go

Use case: you're writing your vector generator in Go and want to call the
`vectorgen` library directly instead of shelling out to the CLI.

The CLI is a thin wrapper over `github.com/c2sp/wycheproof/vectorgen`. Go
generators that produce vectors directly can skip the JSON envelope and
call the library functions. The same workflows described above can all be
achieved programmatically.

All examples elide error handling and assume `import "github.com/c2sp/wycheproof/vectorgen"`.
Generators must be built with `GOEXPERIMENT=jsonv2`. Each test or group
object is a `jsontext.Value` (raw JSON bytes) and you can build them however you
like. The library offers `RawObject` (an ordered map) as a convenient helper
when you want deterministic key order, since Go maps serialize alphabetically
through `json/v2`.

Even when calling the library directly, running `scaffold add --schema <name>`
once is worth it: it shows the group and test shapes to build as
`jsontext.Value`s. The same key-order caveat applies: scaffold follows the
schema's `properties` order, and existing files may differ (many put `flags`
right after `comment`; most schemas list it last).

### Adding New Vectors

```go
env := vectorgen.AddEnvelope{
    Tests:     []jsontext.Value{ /* one or more test objects */ },
    IntoGroup: "github/aws/aws-lc", // or "name@version"
}
err := vectorgen.Add("testvectors_v1/mlkem_512_semi_expanded_decaps_test.json",
    env, vectorgen.Options{})
```

To append a new group instead, drop `IntoGroup` and set `env.GroupTemplate`
(a `jsontext.Value` whose `tests` field is absent — the library fills it
in). To create a brand-new file, also set `Algorithm`, `Schema`, and
optionally `Header`.

### Add or Rewrite a Field of Existing Vectors

```go
env := vectorgen.UpdateEnvelope{
    Source: "github/aws/aws-lc",
    Patches: []jsontext.Value{
        jsontext.Value(`{"tcId": 1, "ek": "..."}`),
        jsontext.Value(`{"tcId": 2, "ek": "..."}`),
    },
    Overwrite: true, // replace existing values
    Partial:   true, // patch a subset
}
err := vectorgen.Update("testvectors_v1/mlkem_512_semi_expanded_decaps_test.json",
    env, vectorgen.Options{})
```

For glob-style multi-file updates, call `Update` once per matching file —
there's no library-level glob helper.

### Replace a Whole Group of Vectors

```go
env := vectorgen.AddEnvelope{
    GroupTemplate: jsontext.Value(`{
        "type": "MLKEMDecapsValidationTest",
        "source": {"name": "github/lukaszobernig/reenc", "version": "2.0"},
        "parameterSet": "ML-KEM-512"
    }`),
    Tests: []jsontext.Value{ /* new tests */ },
}
filter := vectorgen.ParseSourceFilter("github/lukaszobernig/reenc@1.0")
err := vectorgen.Replace("testvectors_v1/mlkem_512_semi_expanded_decaps_test.json",
    env, filter, vectorgen.Options{})
```

### Other Useful Entry Points

- `vectorgen.ScaffoldAdd(schemaName, opts) ([]byte, error)` — same JSON
  skeleton the CLI produces.
- `vectorgen.LintBytes(data, schemasFS) error` — validate an in-memory
  buffer against a schema; returns the sentinel `ErrNoSchema` when the
  vector declares no schema.
- `vectorgen.FormatBytes(in) ([]byte, error)` — canonical formatter for
  one-off bytes; `FormatFile` / `CheckFormatFile` operate on disk.
- `vectorgen.Options{SchemasFS: os.DirFS("schemas")}` — override the
  embedded `wycheproof.Schemas` (useful when developing schemas alongside
  vectors).

[JSON schema]: https://json-schema.org/
[schema dir]: https://github.com/C2SP/wycheproof/tree/main/schemas
[schema lint]: https://github.com/C2SP/wycheproof/blob/main/.github/workflows/vectorlint.yml
[source schema]: https://github.com/C2SP/wycheproof/blob/main/schemas/common.json
[schema ref]: https://json-schema.org/understanding-json-schema/structuring#dollarref
