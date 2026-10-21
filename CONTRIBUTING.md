# Contributing

Describe the problem and proposed behavior before submitting a substantial change. Include focused tests and explain how you validated it. Keep changes to scanning scope, authorization, template policies, and organization isolation explicit and reviewable.

Use synthetic fixtures or sanitized local-lab fixtures. Never include a real environment file, passwords, tokens, verification material, database dumps, raw scan evidence, or customer reports in issues or commits.

Run frontend tests from `frontend/`. Run backend tests against an isolated disposable test database. Live scans require explicit target authorization.

Contributions to BEACON source are made under the MIT License. Keep third-party copyright and license notices intact. Fresh-install validation remains a release priority.
