Want to contribute? Great!

### Before you contribute
Before you start working on a larger contribution, you should get in touch with
us first through the issue tracker with your idea so that we can help out and
possibly guide you. Coordinating up front makes it much easier to avoid
frustration later on.

### Disclosure
If your tests uncover security vulnerabilities, please first report directly to
the maintainers of the libraries. You should only submit tests to us once the
bugs have been acknowledged or fixed.

### Code reviews
All submissions, including submissions by project members, require review. We
use GitHub pull requests for this purpose.

### Test schemas
All new test types should be accompanied by [JSON schema] files describing the
test vector data structure. See the [`schemas/` directory][schema dir] for
existing examples.

Test vector files are [linted in CI][schema lint] against their schemas. You can
run the lint locally after installing Go with `go run ./tools/vectorlint`.

#### Schema best practices

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

[JSON schema]: https://json-schema.org/
[schema dir]: https://github.com/C2SP/wycheproof/tree/main/schemas
[schema lint]: https://github.com/C2SP/wycheproof/blob/main/.github/workflows/vectorlint.yml
[source schema]: https://github.com/C2SP/wycheproof/blob/main/schemas/common.json
[schema ref]: https://json-schema.org/understanding-json-schema/structuring#dollarref

### Test vector best practices

All new JSON test vector files should:

* Reference a schema.
* Be placed in the `testvectors_v1/` directory.
* Divide individual JSON files by the most important algorithm parameter (e.g.
  key size). When convenient, try to split the test vectors so that consumers
  that may not support all variations of the algorithm can test with specific
  vector files without needing additional post-filtering.

####  Choosing a source name

The common [source schema] allows specifying a name and version for your new
test vectors.

We intend to use the source element to allow targetted updates to test vector
data identified by the source name/version. For this reason, when augmenting
existing vector files with new data try to choose a source name that will be
specific enough for future regeneration without affecting unrelated data.

For example, using source name "github/myusername/weak_params" for new vector
data added to `imaginary_algorithm_2048_test.json` may be preferrable to
"github.com/myusername" if you intend to add other kinds of test vectors to
`imaginary_algorithm_2048_test.json` in the future, and would want to be able to
update those separately from the weak parameter test vector data.
