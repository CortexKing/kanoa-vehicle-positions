# SAEIV authenticated telemetry integration

The production KANOA integration is based on upstream commit
`08cc246f3ce01ff36e4700b8cc1130715593e65b`, preserving the runtime behavior of
the inventoried production image. Its production image is
`onebusaway-vehicle-positions:production-resources-v1`, staged image ID
`sha256:270a3da95e24b1747face2bb8a4c938178f8d1ad806bf39d13166f2a3463d24f`.
The maintained fork is `CortexKing/kanoa-vehicle-positions`; upstream remains
`OneBusAway/vehicle-positions`. Upstream main has advanced substantially and
is not automatically merged into the tested production branch.

`POST /api/v1/integrations/saeiv/locations` validates a dedicated service JWT, then calls the existing location handler. Configuration: `SAEIV_INGEST_SECRET_FILE` points to a protected secret file of at least 32 bytes, shared only with SAEIV backend. Missing configuration returns 503. Legacy authentication and routes remain unchanged.

HS256 only; issuer `kanoa-saeiv`; audience `vehicle-positions-ingest`; required expiry; issued-at; maximum lifetime 30 seconds; driver ID subject; nonce; SHA256 of exact body. Tampering and in-process replay return 401. The bounded replay cache is process-local and resets on restart. The integration token does not authorize legacy driver/admin routes. No PostgreSQL driver user or association is required for this telemetry path.

The existing handler retains coordinate, timestamp and rate-limit validation and telemetry persistence. Verify source rate-limit settings against the built image before playback; do not assume image identity from its tag.

Go formatting, normal tests and race tests passed in the production staging
build on Docker Host. The production container started successfully, the
GTFS-RT endpoint returned 200, and unauthenticated native ingestion returned
401. Production native GPS verification is deferred, including successful
location forwarding and GTFS-RT propagation. The unit tests cover expiry,
body tampering, replay, wrong key and dedicated token boundaries.
