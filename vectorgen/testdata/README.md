# vectorgen test fixtures

Each fixture is a worked example of a `doc/vectorgen.md` workflow, replayable
with the CLI (see each fixture's README for the exact command). Where
possible, before/after states are byte-identical copies of real commits, so
the tests replay actual contribution history.

| Fixture | doc/vectorgen.md section | Provenance |
| --- | --- | --- |
| [`add_pr255/`](add_pr255/) | A Whole New File | [PR #255] (commit [`1812c93`]) |
| [`add_pr254c2/`](add_pr254c2/) | A New Group in an Existing File | [PR #254] commit 2 ([`44dcf46`]) |
| [`add_intogroup/`](add_intogroup/) | New Tests in an Existing Group | synthetic test appended to [PR #254]'s state |
| [`update_pr254c1/`](update_pr254c1/) | Add or Rewrite a Field | [PR #254] commit 1 ([`f0b4b70`]) |
| [`update_rewrite/`](update_rewrite/) | Add or Rewrite a Field (`--overwrite`) | synthetic |
| [`replace_reenc/`](replace_reenc/) | Replace a Whole Group | synthetic, modeled on real removals ([`2abbf88`]) |

[PR #254]: https://github.com/C2SP/wycheproof/pull/254
[PR #255]: https://github.com/C2SP/wycheproof/pull/255
[`1812c93`]: https://github.com/C2SP/wycheproof/commit/1812c93fea09a7c7eb385ffd0ff41ae63514918d
[`44dcf46`]: https://github.com/C2SP/wycheproof/commit/44dcf469edba24279ff29c2875d27313075296d1
[`f0b4b70`]: https://github.com/C2SP/wycheproof/commit/f0b4b70e5bca133a9afe3f725af87922ee900bd9
[`2abbf88`]: https://github.com/C2SP/wycheproof/commit/2abbf8892a895cc2ef878a8cff474d1963d071ff
