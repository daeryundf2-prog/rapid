# Release Signing Runbook

Status: prepared, not executed (requires external certificates and accounts)
Created: 2026-08-30
Authority: roadmap Phase 4; `docs/rapidtriage-release-checklist.md`; `windows-installer-workflow-manifest-v1` and `macos-package-workflow-manifest-v1` evidence slots.

This runbook gives the exact commands an operator runs on each platform to turn the
unsigned release payloads produced by `scripts/build-release.py` into signed,
notarized packages. It does not create certificates or Apple/OS identities, and it is
not itself signing evidence — attach the tool transcripts and hashes to the release
evidence bundle afterwards.

## Inputs Required (external)

| Platform | Requirement |
| --- | --- |
| Windows | EV (or OV) code signing certificate + private key (HSM/token or PFX), timestamp server URL, `signtool.exe` (Windows SDK) |
| macOS | Apple Developer ID Application certificate, App Store Connect API key for notarytool, macOS host with Xcode CLT |
| Linux | Packaging host with `dpkg-deb`/`rpmbuild` (or `fpm`), optional GPG key for repo signing |

## Windows: Authenticode signing

```powershell
# 1. Build the unsigned payload
py -3.12 -m pip install -e .
python scripts/build-release.py --output-dir release

# 2. Sign the EXE/MSI payloads (repeat for every launcher binary)
signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 ^
  /f cert.pfx /p <pfx-password> ^
  release\rapidtriage-portable.zip.enclosed-launcher\*.exe

# 3. Verify signature and timestamp chain
signtool verify /pa /all /tw release\*.exe

# 4. Record evidence
Get-AuthenticodeSignature release\*.exe |
  Select-Object Path, Status, @{n='Thumbprint';e={$_.SignerCertificate.Thumbprint}} |
  ConvertTo-Json | Out-File release\windows-signing-evidence.json
sha256sum release\*.exe > release\windows-signing-sha256.txt
```

Attach `windows-signing-evidence.json` + `windows-signing-sha256.txt` to the
release evidence bundle `windows-installer-workflow-manifest-v1` slots.

## macOS: codesign + notarization

```bash
# 1. Build payload on a macOS host
python3.12 -m pip install -e .
python scripts/build-release.py --output-dir release

# 2. Codesign every Mach-O binary and the app bundle
codesign --force --timestamp --options runtime \
  --sign "Developer ID Application: <name> (<team-id>)" \
  release/<payload>/*.dylib release/<payload>/*.so

# 3. Notarize and staple
xcrun notarytool submit release/<payload>.zip \
  --keychain-profile "rapidtriage-notary" --wait
xcrun stapler staple release/<payload>.zip

# 4. Verify and record
spctl assess --type execute -vv release/<payload>
codesign --verify --strict --verbose=2 release/<payload>
shasum -a 256 release/* > release/macos-signing-sha256.txt
```

Attach Gatekeeper assessment output and notarytool log to the
`macos-package-workflow-manifest-v1` slots.

## Linux: deb / rpm / AppImage

```bash
# deb (fpm example; dpkg-deb works from a control-dir layout too)
fpm -s dir -t deb -n rapidtriage -v 0.2.0 \
  --description "Local-first rapid forensic triage console" \
  --license "Proprietary" \
  release/rapidtriage-portable/=/opt/rapidtriage

# rpm
fpm -s dir -t rpm -n rapidtriage -v 0.2.0 \
  --description "Local-first rapid forensic triage console" \
  release/rapidtriage-portable/=/opt/rapidtriage

# AppImage (linuxdeploy appdir workflow)
./linuxdeploy --appdir AppDir --output appimage

# Install/uninstall smoke (must be captured in a clean container)
docker run --rm -v "$PWD:/pkg" ubuntu:24.04 bash -c \
  "apt install -y /pkg/rapidtriage_0.2.0_amd64.deb && rapidtriage doctor && apt remove -y rapidtriage"
sha256sum rapidtriage_0.2.0_amd64.deb rapidtriage-0.2.0.x86_64.rpm RapidTriage-x86_64.AppImage
```

## Evidence Closure

For each platform, attach to the release evidence bundle:

1. Signing/notarization tool transcript (unredacted command lines with secrets removed).
2. Verification output (`signtool verify`, `spctl`, `codesign --verify`, install/uninstall smoke).
3. SHA-256 of every signed artifact, linked into `SHA256SUMS`.
4. Certificate identity and thumbprint (Windows) / team ID (macOS).
5. A dated operator note naming who performed the signing.

The release verifier (`scripts/verify-release-evidence.py`) only accepts the signing
evidence when the artifacts it hashes match the released payload set.
