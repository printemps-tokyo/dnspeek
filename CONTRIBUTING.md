# Contributing

Thanks for your interest in contributing to a printemps-tokyo project.

## Development

1. Fork / clone the repository
2. `npm install`
3. Create a branch: `git switch -c feat/your-change`
4. Make your change and verify locally:
   ```bash
   npm run lint
   npm run typecheck
   npm test
   ```
5. Commit and open a pull request

## Commit messages

[Conventional Commits](https://www.conventionalcommits.org/) are preferred
(`feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`).

## Pull requests

- Keep one PR focused on a single purpose
- CI (lint / typecheck / test / build) must be green
- Update the README and tests when behavior changes

## Bug reports and requests

Please open an [issue](../../issues) using the templates.
