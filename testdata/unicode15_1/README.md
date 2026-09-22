# Unicode 15.1 source data

`DerivedAge.txt` is the Unicode Character Database 15.1.0 source from
<https://www.unicode.org/Public/15.1.0/ucd/DerivedAge.txt>. Its SHA-256 is
`04e16379344bdb9973cdb6f6bf0a5dd66f7cd41b014cd9f79d848768ae757256`.

`LICENSE.txt` is the Unicode license from <https://www.unicode.org/license.txt>.
Its SHA-256 is
`e7a93b009565cfce55919a381437ac4db883e9da2126fa28b91d12732bc53d96`.

Run `node testdata/unicode15_1/generate_tables.mjs --check` to prove that the
Go, Rust, Swift, and TypeScript acceptance tables are byte-for-byte generated
from this single source. Newer platform libraries may provide normalization,
Punycode, Bidi, and ContextJ algorithms, but cannot expand the accepted scalar
set.

`normalization_sources.json` pins the official Unicode 15.1 `UnicodeData.txt`,
`DerivedNormalizationProps.txt`, and complete `NormalizationTest.txt` corpus.
The same Unicode license applies to these data files. They generate
`normalization_generated.json`, containing canonical combining classes,
decompositions, non-excluded composition pairs and assigned scalar ranges.
`node testdata/unicode15_1/generate_normalization.mjs --check` verifies all source
hashes and compares that generated table without writing files. To import exact
source files already downloaded from the recorded URLs, use
`--import-sources /absolute/source/directory`; mismatched or existing different
files are rejected before replacement.

The v4 reference tooling implements NFC from these fixed tables, including
Hangul, without platform normalization. The official conformance corpus and
all remaining scalar invariance cases run in
`scripts/transport-v4-unicode.test.mjs`. Encoding and decoding require original
canonical text; explicit construction code may call the normalizer separately.
`idna_sources.json` pins the additional official Unicode 15.1 IDNA/UCD sources.
`generate_idna.mjs` derives RFC5892 properties with fixed-data NFKC/casefolding
and generates UTS46 mappings, scripts, joining types, categories and Bidi data.
It accepts `--check` and `--import-sources /absolute/source/directory` with the
same source-integrity and no-overwrite rules. The resulting
`idna_generated.json` is consumed by the reference tooling; it uses UTS46
revision 31, RFC3492, RFC5892 contextual validity and RFC5893 domain-wide Bidi.

`scripts/transport-v4-idna.test.mjs` runs every official nontransitional ToASCII
case and separate Flowersec DNS rules. These include the mandatory IDNA2008
and ContextO predicates beyond UTS46, no trailing dot and strict wire A-label
round-trips. Complete IP/Origin/route validation and four-SDK text processing
remain unqualified. Reference results do not qualify SDK allocation behavior.
