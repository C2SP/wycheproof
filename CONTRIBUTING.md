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

### Adding or updating test vectors

Use the `vectorgen` tool for test vector changes rather than hand-editing
JSON. It can create new vector files, append new groups or tests, patch
fields across existing vectors, and replace regenerated groups. In all cases
it takes care of `tcId` assignment, `numberOfTests`, canonical formatting,
and schema validation.

See [doc/vectorgen.md](./doc/vectorgen.md) for the workflows, along with
schema and test vector best practices (including how to choose a source name
for new vector data).

### Language specific ecosystem considerations

Many programming language ecosystems have some sort of package distribution
infrastructure (e.g. [Packagist], [PyPI], [crates.io], and many more). We're
generally supportive of efforts to make Wycheproof test vectors easy to
consume through those language specific ecosystems, but have some guidelines
to help keep the maintenance burden manageable:

1. We are happy to take contributions that add metadata and small bits of 
   supporting code, but they should be focused on distributing the JSON data.
   We are **not** able to take contributions that provide deserialization types
   or in-memory representations that need to be kept in-sync with the JSON.
   Similarly, contributions that require extensive tooling/code are likely to
   be declined.
2. We rely on the contributor to agree to help with continued maintenance. Each
   ecosystem has its own best practices that members of that community are best
   positioned to enforce. Similarly, as the ecosystem in question evolves we 
   expect the original contributor to help keep the Wycheproof side in working 
   condition, or we may remove the integration.
3. Where possible, updates should be automatic, and performed as part of our
   regular development cycle without needing additional manual steps. E.g. 
   if we merge new vector data, or publish a new tag, the packaged version 
   should be updated through CI or some other automated integration.

A positive example to compare against is our [PHP ecosystem integration] with
[Packagist].

[Packagist]: https://packagist.org/
[PyPI]: https://pypi.org/
[crates.io]: https://crates.io/
[PHP ecosystem integration]: ./composer.json
