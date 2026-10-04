# Spotibuds Identity

Identity runs alongside the sibling `Frontend`, `Music` and `User` repositories.
The authoritative local setup and environment matrix are in
[`Frontend/demo/README.md`](../Frontend/demo/README.md). From the workspace parent
of these four repositories, use PowerShell:

```powershell
pwsh -File Frontend/demo/New-LocalEnvironment.ps1
pwsh -File Frontend/demo/Demo.ps1 -Action start
pwsh -File Frontend/demo/Demo.ps1 -Action seed
```

Generated local account credentials stay in the ignored account file. Identity
runs at `http://127.0.0.1:5101`, the frontend at `http://127.0.0.1:3100`, and the
actual recovery inbox at `http://127.0.0.1:8025`. Keep the host name consistent.
Shared JWT issuer and audience are `spotibuds-local` and `spotibuds-demo`.
Identity GUIDs identify actors; Mongo ObjectIds identify profile documents.

The full [session, account and synchronization contract](docs/LOCAL-CONTRACT.md)
documents HttpOnly refresh cookies, immediate logout/password revocation,
private account boundaries, administrator permissions, typed internal service
routes and durable reconciliation. [`.env.example`](.env.example) lists mandatory
settings without operational credentials. No cloud or historical configuration
is used as a fallback.

Deployments without an email relay can explicitly set `Smtp__Enabled=false`.
Sign-in remains available; password-reset requests return a clear 503 without
creating a reset token or disclosing whether the account exists. When enabling
email, configure `Smtp__Host`, `Smtp__Port` and `Smtp__From` first. The current
mailer expects a trusted SMTP relay without authentication or TLS; do not expose
that relay publicly.

From this repository, verify locally with:

```powershell
dotnet build Identity.sln -c Release
dotnet test tests/Identity.Tests/Identity.Tests.csproj -c Release
```

From the workspace, `node Frontend/demo/identity-integration.mjs` additionally
asserts real PostgreSQL, Mongo and Mailpit state. The CI workflow validates
builds, regressions, dependency advisories and the container without deployment.
