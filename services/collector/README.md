# Database Security Assurance Collector

The collector is an outbound-only runtime intended to run inside a customer
network close to the databases it assesses. It executes only the immutable
probe catalogue in this package, uses read-only database identities, and sends
bounded security metadata to the Assurance Hub API. It never accepts SQL from
an API payload and never logs or persists source credentials.

The four driver integrations are optional because Oracle and SAP driver
licensing and supported version matrices must be approved by the customer. A
production image installs only the approved driver extras. Until representative
database, Vault, PKI, and workload-impact tests pass, job leasing must remain
disabled.

Secrets are projected by the enterprise secret manager into a private mounted
directory. Each secret is stored as JSON in a file named with the lowercase
SHA-256 digest of its canonical secret reference plus `.json`. This avoids
putting secret-manager paths or credential material in process arguments or
environment variables.

The current implementation includes strict configuration, safe endpoint
parsing, bounded query execution, metadata allowlisting, digest generation,
read-only adapters, and driver-independent unit tests. Customer-environment
integration and negative-write tests remain a production promotion gate.
