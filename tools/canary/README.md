# Canary VM (release gate)

Spec: "Testing and quality" → Canary VM and Protected-data check. No release
ships unless this run passes.

Never run these scripts on a development machine: the clean step deletes
files. They belong in the canary VM only.

## One-time setup (host)

1. Enable Hyper-V (elevated PowerShell, then reboot):
   `Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All`
2. Get a Windows 11 Enterprise evaluation ISO (90 days, free) from the
   Microsoft Evaluation Center. Windows 10 22H2 follows for the QA matrix.
3. Create the VM (elevated): `.\New-CanaryVM.ps1 -IsoPath <iso>`.
   It lives in `E:\HyperV\PurgeKit-Canary` (drive C has too little space).

## One-time setup (guest)

1. Install Windows with a local **admin** account (UAC on, the default).
   Turn off Windows Update for the run window (pause updates for 5 weeks).
2. Install Chrome, Edge (built in), Firefox, Discord, Spotify, VS Code,
   Cursor, Slack, Teams, Steam. Open each one and use it a little so it
   writes real caches.
3. Protected data, with throwaway test accounts only:
   - In each browser, save 3 passwords and 5 bookmarks (no sync).
   - `cmdkey /generic:canary-test /user:canary /pass:<anything>` (Credential Manager).
   - Write down the passwords/bookmarks you saved; the final check is by eye.
4. Copy the repo's `rules\`, `tests\fixtures\rules\`, `tools\canary\` and a
   release build of `purgekit.exe` + `purgekit-helper.exe` into
   `C:\Canary\repo` in the VM (Enhanced Session drive redirection, or
   `Copy-VMFile`). The manifest skips `C:\Canary`.
5. Close every app. Take the checkpoint **base**. Disconnect the network
   (`.\New-CanaryVM.ps1 -Offline` on the host): the run is offline.

## Control run (once per base checkpoint)

Shows what Windows changes by itself, without PurgeKit.

```powershell
.\Seed-Canary.ps1 -RepoDir C:\Canary\repo
.\Get-CanaryManifest.ps1 -Label control-pre
# wait as long as a real clean takes (about 5 minutes), do nothing
.\Get-CanaryManifest.ps1 -Label control-post
.\Compare-Canary.ps1 -Control
```

Review `control-changes.txt`. Copy only harmless lines from
`noise-suggested.txt` into `noise.txt` and commit them. Restore **base**.

## Canary run (every release candidate)

1. Restore checkpoint **base**. Make sure the network is off.
2. Elevated PowerShell in the guest:
   ```powershell
   .\Seed-Canary.ps1 -RepoDir C:\Canary\repo
   .\Get-CanaryManifest.ps1 -Label pre
   ```
3. Start PurgeKit (not elevated). In Settings, show ADVANCED items. Scan,
   check every category including Windows temp and the Recycle Bin, click
   Clean. Count the UAC prompts: exactly one is expected.
4. Close PurgeKit, then in the elevated shell:
   ```powershell
   .\Get-CanaryManifest.ps1 -Label post
   .\Compare-Canary.ps1
   ```
5. Open each browser: the saved passwords and bookmarks must all be there.
   `cmdkey /list` must show `canary-test`.
6. Keep `C:\Canary\canary-report.txt` with the release notes.

The verdict is FAIL on any change outside the cleaned areas (after
`noise.txt`), any protected or KEEP file changed or gone, any trap gone or
victim file changed, a rule root removed, or measured recovery more than 10%
away from the estimate. `allowed.txt` is a hand-written second opinion of
where removals may happen; keep it in step with `rules\*.toml`.
