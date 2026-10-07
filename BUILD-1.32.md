# FckZck Revival 1.32 — full-history request

Changes from 1.31:

- Keeps advertised WhatsApp version `2.26.38.74` / bundle `26.38.74`.
- Keeps the 1.29 registration-gate bypass and bootstrap UI release.
- Never spoofs `isInitialSyncFinished`.
- At pair time, searches generated `DeviceProps` protobuf classes and forces `requireFullSync = YES` when the field exists.
- Raises HistorySyncConfig limits when matching generated setters exist: 365 days, 512 MB full sync, 1024 MB storage quota, 90 days recent sync, and on-demand ready.
- Logs exactly which DeviceProps/HistorySyncConfig classes and setters were found/hooked.
- Narrows the Range workaround: it now strips `Range` only for exact `directPath` values observed in actual HistorySyncNotification messages, instead of all WhatsApp `mode=manual` .enc traffic.

The full-history request only matters on a fresh pairing. Unlink the iPhone 6 from the primary and pair again.
