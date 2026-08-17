# AegisDB bounded image metadata reader

This private package is a narrow build-time replacement for `image-size` while
the upstream package has no patched release for GHSA-w3rx-r6r6-pgpr and
GHSA-5p2g-fcmc-qvqq. It reads dimensions only for bounded PNG, GIF, JPEG, WebP,
and SVG metadata assets. ICNS, HEIF, and JXL are rejected immediately and their
vulnerable parsers are not included.
