# Unicode 15.1 assigned-code-point source

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
