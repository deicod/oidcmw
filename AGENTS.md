# Repository Agent Guidelines

Welcome to the repository! Please follow these best practices whenever you make changes.

## Coding Standards
- Format all Go source files using `gofmt` (or `go fmt ./...`) before committing.
- Organize imports with `goimports` if available.
- Prefer small, focused functions and packages. Keep exported APIs documented with GoDoc comments.
- Use clear, descriptive naming; avoid stutter (e.g., `type UserService` in package `user`).
- Handle errors explicitly. Do not ignore returned errors.
- Add unit tests for new functionality and maintain high test coverage.

## Tooling & Checks
- Run `go test ./...` and ensure it passes before creating a PR.
- Run `go vet ./...` to catch common mistakes.
- If `staticcheck` is available, run `staticcheck ./...` for additional linting.

## Git & Commits
- Keep commits focused and well-described. Use imperative tense in commit messages (e.g., "Add authentication middleware").
- Do not commit generated binaries or vendor directories unless explicitly required.

## Documentation
- Update README.md or other documentation when behavior or requirements change.
- Document public interfaces with comments starting with the identifier name.

## Pull Requests
- Summarize key changes and testing performed in the PR description.
- Link related issues when applicable.

Thank you for contributing responsibly!
