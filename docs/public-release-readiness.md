# Public release readiness

This early source release contains source and sanitized test fixtures, not an existing installation's database or operational data.

## Remaining release work

- Complete the exact-version third-party license and notice inventory.
- Enable and test a private vulnerability reporting channel.
- Complete fresh-install acceptance before advertising a ready-to-run release.

## Clean-install gap

Assessment creation selects approved `nuclei_template_snapshots` from the database. The source includes policy and snapshot-building functions, but there is no packaged fresh-install bootstrap command that provisions the required approved snapshots. Migrations alone do not establish that assessments can run. Implement and test a reproducible approval/bootstrap workflow; do not export the production database as a shortcut.

Configure SMTP and complete registration/email verification on a fresh database. Test an explicitly authorized local target through ownership verification, assessment, finding review, cancellation, retest, and HTML/PDF export.

## Known engineering limitations

- The Nuclei health probe uses `nuclei` rather than the configured binary path; the ZAP probe does not use the authenticated assessment client.
- Computed URL coverage infers all authorized URLs are assessed when any web-scanner output exists.
- The total profile deadline is recorded but no orchestration enforcement was found.
- Cancellation is checked between most stages; automatic stale-job recovery wiring was not found.
- Some scanner output limits are checked after subprocess output has already been buffered.
- One shared ZAP daemon uses session and global settings; maintain scanner concurrency of one until concurrent execution is isolated.

## Data handling

Create fresh local secrets and application data for each installation. Keep `.env`, production keys, ownership-verification tokens, user records, database dumps, scanner output, and generated reports out of Git. Never copy an existing deployment's database to bootstrap a public installation.
