# Two flaky tests made deterministic (ws-flaky)

Test change, plus one test-only hook in `internal/store`. No route, listener, table or default changes.

## The failures

1. `TestTimedOutWriteBlocksLaterDelivery` (`internal/sync/delivery_test.go`) bounded the
   whole request with a 50 ms `http.Client.Timeout`. That budget also covers dial and the
   TLS handshake to the `httptest` TLS server, so a starved `-race` process could use it up
   before the handler ran: "request never reached remote". Reproduced 171 of 200 runs
   under load before the fix.
2. `TestALostLeaseEndsTheRunningDeposit` (`cmd/kyidentity/replica_backup_test.go`) shortened
   the backup lease to 800 ms. `HoldLease` gives the first take `ttl/4` (200 ms) and each
   renewal about `ttl/2` (400 ms) of wall-clock time. Under load the renewal missed its
   window ("lease: renewal failed with too little of the lease left") and the lease was lost
   during the snapshot, before the deposit started: "the deposit never started" (CI on
   2a17b04), or the second replica's take missed its budget ("did not deposit"). The test
   also asserted the deposit ended within `ttl/4 + 1s` of wall clock.
   The `no such table: system_settings` lines in the CI log come from
   `TestUnreadableSettingsAreAFailedScheduledRun`, which renames that table on purpose in
   its own database. They are not this test's failure, and the #260 template copy
   (`store.NewTest`) is not involved.

## The fixes

1. The test's transport cancels the first request when the handler is entered. Dial and
   TLS are unbounded, and the write always reaches the remote before it times out, which
   is what the test is about. Later requests pass through, so a write that slipped past the
   fence would still reach the handler and be counted.
2. A test hook, `store.LeaseTicksForTest(t, ch)`, makes lease holders renew on a receive
   from `ch` instead of their ticker until the test ends. The test keeps the production TTL
   (2 min), so no take or renewal budget can be missed. After the steal it sends the one
   renewal that has to notice it. The wall-clock bound is replaced by a signal: the blocking
   depositor reports the cause its context ended with, and the test requires
   `store.ErrLeaseLost`. The test also requires that the deposit was still running and that
   the steal hit a live row. How soon a renewal runs stays with
   `TestALostLeaseEndsTheHold` in `internal/store`.
   A 4 s TTL was tried first and still lost the lease under load: one renewal UPDATE took
   more than 2 s. That is CPU starvation, not lock contention (`VACUUM INTO` was checked
   and does not block writers), so a bigger number cannot fix it.

## Threat model, data, routes, defaults

Production behaviour is unchanged: with the hook unset, `keepLease` uses its ticker as before. The `uncertain` fence and lease-loss cancellation the tests guard are
unchanged. A mutation check (fence write removed from `deliveryTransport`) still fails the
sync test, and passing the scheduler's context instead of the lease's to the deposit
fails the lease test.

## Not built

- No general clock seam. The hook replaces only the renewal ticker, is an atomic pointer
  read once per hold, and takes a `testing.TB`, so only a test can set it.
- The one `database is locked (5)` failure of this test on CI (run 44651600324, at the raw
  steal) was not reproduced, and its cause is unproven.

## Tenancy

No tables. Nothing for multi-tenant mode to follow.
