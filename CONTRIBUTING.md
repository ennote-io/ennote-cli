# Contributing to the Ennote CLI

First off, thank you for considering contributing to Ennote! It's people like you that make our open-source security software robust, reliable, and powerful.

## Security Vulnerabilities
If you discover a security vulnerability, **do NOT open a public issue.** Please refer to our [SECURITY.md](SECURITY.md) for our responsible disclosure process.

## Development Process

1. **Fork the repository** and create your branch from `main`.
2. **Make your changes** in your feature branch.
3. **Generate and Build.** We use gRPC and Protocol Buffers. If you modify `.proto` files, or just need to set up your local workspace, run the generator before building:
   ```bash
   # Generates protobuf stubs and builds the binary
   make build
   ```
4. **Test and Validate.** Ensure your changes do not break existing functionality or introduce data races:
   ```bash
   # Run the test suite with the race detector enabled
   go test -v -race ./...
   
   # Run standard Go heuristics
   go vet ./...
   ```
5. **Local Security Scanning.** We enforce strict security gates in our CI/CD pipeline. Please scan your code locally before opening a Pull Request:
   ```bash
   # Check for unsafe code patterns
   gosec ./...
   
   # Check for known vulnerabilities in dependencies
   govulncheck ./...
   ```
6. **Commit your changes.** Write clear, descriptive commit messages. **Do not commit generated `.pb.go` files.**
7. **Open a Pull Request.** Ensure your PR description clearly describes the problem and the solution. Link any relevant open issues.

## Pull Request Requirements

* All PRs must pass the automated GitHub Actions validation pipeline (`pr.yml`), which includes unit tests, `gosec`, and `govulncheck`.
* If you are introducing a new command or feature, please update the relevant documentation and `README.md`.
* We review PRs weekly and will provide constructive feedback!

## License
By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.