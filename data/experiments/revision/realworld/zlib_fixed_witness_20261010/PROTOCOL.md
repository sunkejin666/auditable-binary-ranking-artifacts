# zlib `Z_FIXED` witness probe (2026-10-10)

This is an isolated, retrospective verification of the zlib 1.2.11 change-log
entry “Fix a bug that can crash deflate on some input when using `Z_FIXED`”. It
does not claim an independent discovery. The probe uses only the public zlib
API (`deflateInit2`, `deflate`, and `deflateEnd`) and deterministic generated
inputs. The harness is compiled together with each version under GCC AddressSanitizer
and UndefinedBehaviorSanitizer.

The affected version is 1.2.11; 1.2.12 is the fixed control. Each case varies
input size, six deterministic input families, seed, compression level, memory
level, input chunk size, and (for two families) `Z_SYNC_FLUSH`. A case is a
failure only for a non-zero process status, sanitizer report, or a bounded
timeout. A clean run is evidence that this corpus did not reproduce the known
issue; it is not evidence that the issue is absent.

The run directory is intentionally separate from earlier validation outputs.
The manifest records source-file and harness hashes, arguments, return codes,
elapsed time, and truncated diagnostics. No source or result from the main
ranking experiment is overwritten.
