# MSIX packaging spike

Spec: "Distribution and updates". Ruling: spike MSIX first; if any of its
three risks bites, ship a signed MSI for 0.1.

The test certificate made by `Build-Msix.ps1` is for the spike VM only.
Never publish a package signed with it.

## Tools

Install only the Windows SDK signing tools (makeappx + signtool), on drive E:
(elevated; `winsdksetup.exe` from the Windows SDK download page):

```powershell
.\winsdksetup.exe /features OptionId.SigningTools /installpath "E:\Windows Kits\10" /quiet /norestart
```

## Build

```powershell
. .\env.ps1
cargo build --release -p purgekit -p purgekit-helper
.\tools\msix\Build-Msix.ps1 -Variant virtualized
.\tools\msix\Build-Msix.ps1 -Variant unvirtualized
```

## Install in the canary VM (from checkpoint base, never on the dev machine)

```powershell
Import-Certificate -FilePath PurgeKitSpike.cer -CertStoreLocation Cert:\LocalMachine\TrustedPeople
Add-AppxPackage .\PurgeKit-virtualized.msix
```

## Test matrix (run each test for both variants)

| # | Risk | Test | Pass when |
|---|------|------|-----------|
| 1 | AppData virtualization | Run the canary (`tools\canary`) with the packaged app. | Same verdict as the unpackaged build; the DELETE fixtures are gone when checked from a normal, unpackaged shell (not only hidden from the package's view). |
| 1b | | Scan only. Compare the candidate list and sizes with the unpackaged build. | Identical: the package sees the real caches. |
| 1c | | Check where `settings.json`, `history.json` and `logs\` were written. | Note the path (real `%LOCALAPPDATA%\PurgeKit` or `%LOCALAPPDATA%\Packages\PurgeKit.Spike_*\LocalCache\...`). |
| 2 | Helper elevation | Select Windows temp, clean. | Exactly one UAC prompt; the helper runs elevated; the pipe PID check passes; Windows temp fixtures are cleaned. |
| 2b | | Same, from a standard (non-admin) account. | Over-the-shoulder UAC works. |
| 3 | Uninstall | `Remove-AppxPackage`, then look for PurgeKit data. | Record what stays and what is removed, and whether any prompt was possible. |
| 4 | Store policy | Desk check (below). | No policy blocks a cleaner. |

Record each result in the spike report with the Windows build number.

## Desk findings (2026-10-08, to confirm in the tests)

- Microsoft's MSIX docs say deletes of existing files under the real AppData
  are allowed for packaged full-trust apps; only *new* files are redirected.
  PurgeKit deletes through handle-relative `NtCreateFile` +
  `FileDispositionInfoEx`, which the docs do not cover: test 1 decides.
- Microsoft Store Policies 7.20, section 10.2.9 lets a non-game product be
  listed in the Store with a signed `.msi`/`.exe` download URL (silent
  install, UAC allowed). So the Store is reachable without MSIX too.
- Section 10.2.7 requires a clean uninstall. No section bans cleaner apps.
  The restricted capabilities `allowElevation` and `unvirtualizedResources`
  need a written justification at Store submission.
- **Spec conflict:** the spec says uninstall "asks before deleting
  `%LOCALAPPDATA%\PurgeKit`". MSIX has no uninstall UI: redirected app data
  is removed silently, unredirected data stays silently. With MSIX this
  requirement cannot be met as written.
