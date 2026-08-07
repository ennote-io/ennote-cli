# Ennote Security CLI

The Identity-Driven Secret Manager CLI. Ennote provides secure, programmatic access to your infrastructure secrets, tokens, and certificates directly from your terminal and CI/CD pipelines.

📚 **[Read the Official Documentation](https://docs.ennote.io/cli/overview)**

---

## 🚀 Installation

We provide signed, pre-compiled binaries for all major operating systems.

### macOS & Linux (Homebrew)
```bash
brew install ennote-io/tap/ennote
```

### Windows (Scoop)
```powershell
scoop bucket add ennote-io https://github.com/ennote-io/scoop-bucket
scoop install ennote
```

### Universal Shell Script (CI/CD)
For headless environments, Alpine Linux, or raw CI/CD runners:
```bash
curl -1sLf https://get.ennote.io/get-cli.sh | sh
```

### Manual Download
Pre-compiled binaries, `.deb`, `.rpm`, and `.apk` packages are available on our [Releases Page](https://github.com/ennote-io/ennote-cli/releases).

---

## 🔒 Security & Provenance

Enterprise security is our foundational principle. Every release is entirely automated and cryptographically verifiable.

* **Software Bill of Materials (SBOM):** We attach a standard SPDX/CycloneDX SBOM (`.sbom.json`) to every compiled artifact.
* **Keyless Signatures:** All release checksums are signed using Sigstore Cosign via GitHub OIDC tokens.
* **Zero Persistence:** No human developer possesses the cryptographic keys to publish or sign a release.

To verify a release manually using Cosign:
```bash
cosign verify-blob \
  --certificate dist/checksums.txt.pem \
  --signature dist/checksums.txt.sig \
  --certificate-identity "[https://github.com/ennote-io/ennote-cli/.github/workflows/release.yml@refs/tags/vX.Y.Z](https://github.com/ennote-io/ennote-cli/.github/workflows/release.yml@refs/tags/vX.Y.Z)" \
  --certificate-oidc-issuer "[https://token.actions.githubusercontent.com](https://token.actions.githubusercontent.com)" \
  dist/checksums.txt
```
