# Third-party notices

The project's own source code is licensed under Apache-2.0. Dependencies retain
their own licenses; this notice does not change the license of the project.

## Compression backend

The RFB Zlib and ZRLE encodings use `flate2` with its `rust_backend` feature.
This is a pure-Rust backend and does not link against the system zlib library.

- `flate2`: MIT OR Apache-2.0
- `miniz_oxide`: MIT OR Zlib OR Apache-2.0
- `adler2`: 0BSD OR MIT OR Apache-2.0
- `crc32fast`: MIT OR Apache-2.0
- `simd-adler32`: MIT

These are the license expressions declared by the locked crate versions. Their
license texts and source are available from the corresponding crate packages
and repositories on crates.io.
