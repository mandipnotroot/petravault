<!--
SPDX-FileCopyrightText: 2026 Petravault Contributors
SPDX-License-Identifier: GPL-3.0-only
-->

# Commit Message Guide

This project uses **[Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/)**.
The specification is the authority on message format. This file is a quick
reference to it, plus the few project rules the specification does not cover
(scopes, commit size, and no tool attribution).

If this file and the specification ever disagree on format, the specification wins.

## Format

```
<type>[optional scope][!]: <description>

[optional body]

[optional footer(s)]
```

- The type, the optional scope, the optional `!`, and the colon plus space are the prefix. A description must follow immediately.
- The body starts one blank line after the description and is free-form (any number of paragraphs).
- Footers start one blank line after the body.
- The units of a commit message are not case-sensitive, except `BREAKING CHANGE`, which must be uppercase. Pick one casing (lowercase) and keep it.

## Types

`feat` and `fix` are the only types the specification defines. The others come from
`@commitlint/config-conventional` (the Angular convention) and are the ones this project allows.

| Type       | Use for                                    | SemVer effect                |
|------------|--------------------------------------------|------------------------------|
| `feat`     | A new feature                              | MINOR                        |
| `fix`      | A bug fix                                  | PATCH                        |
| `docs`     | Documentation changes only                 | none                         |
| `style`    | Formatting, whitespace (no logic change)   | none                         |
| `refactor` | Restructuring without behavior change      | none                         |
| `perf`     | Performance improvements                   | none                         |
| `test`     | Adding or updating tests                   | none                         |
| `build`    | Build system or dependency changes         | none                         |
| `ci`       | CI/CD configuration changes                | none                         |
| `chore`    | Maintenance that fits nowhere else         | none                         |
| `revert`   | Reverting a previous commit (see below)    | none                         |

Types other than `feat` and `fix` have no SemVer effect unless the commit is a breaking change.
Use a type from this table. A type that is not in the table (for example `feet:` for `feat:`) is
not an error in git, but tooling built on the specification will silently skip that commit.

If a change fits more than one type, split it into more than one commit.

## Scope

A scope is optional. It is a noun for the part of the codebase that changed, in parentheses:
`fix(restore): ...`. This repository uses these scopes:

| Scope        | Covers                                            |
|--------------|---------------------------------------------------|
| `backup`, `chunking`, `pack`, `compression`, `config`, `crypto`, `erasure`, `identity`, `manifest`, `repository`, `restore`, `scheduler`, `verify` | the matching package under `internal/` |
| `cli`        | `cmd/` and command wiring                         |
| `deps`       | dependency updates (`build(deps): ...`)           |
| `release`    | release and packaging scripts                     |

Leave the scope out when a change spans many packages. Add a new scope only when a new package or
area appears. All examples in this guide use scopes from the table above.

## Breaking changes

A breaking change is marked in either way (or both):

- a `!` immediately before the colon: `feat(config)!: rename DB_URL to DATABASE_URL`
- a footer that starts with the uppercase token `BREAKING CHANGE:` (`BREAKING-CHANGE:` is a synonym)

Any type can be breaking, and a breaking change correlates with a MAJOR release. When `!` is used,
the description must make the break clear, and the footer may be omitted.

In this project, treat these as breaking: a change to the on-disk repository format or crypto suite
identifiers, a removed or renamed CLI command or flag, a changed exit code, or a removed or renamed
config key or environment variable.

## Footers

A footer is a `token: value` or `token #value` line, following the
[git trailer](https://git-scm.com/docs/git-interpret-trailers) convention. Tokens use `-` instead of
spaces (`Reviewed-by`), with `BREAKING CHANGE` as the one exception.

- Reference tracked work by ID, in whatever tracker you use: `Refs: ISSUE-123`
- Record reviewers or similar people-based trailers if your workflow uses them: `Reviewed-by: Name`

## Reverts

The specification leaves reverts to tooling. The recommendation, and this project's rule, is the
`revert` type plus a footer listing the reverted commit SHAs:

```
revert: feat(cli): add pagination to user list

Refs: a1b2c3d
```

## Examples

### No body

```
docs: correct spelling of CHANGELOG
```

### With scope

```
fix(identity): handle expired token on login
```

### Body and footers

```
fix(restore): prevent racing of chunk reads

Introduce a request id and a reference to the latest read. Dismiss
incoming results other than from the latest read.

Refs: ISSUE-142
```

### Breaking change with `!`

```
feat(cli)!: drop the --legacy-format flag
```

### Breaking change with a footer

```
refactor(config): rename env variable DB_URL

BREAKING CHANGE: DB_URL is now DATABASE_URL.
Update your .env files before deploying.
```

### Both `!` and a footer

```
feat(config)!: reject unknown config keys

BREAKING CHANGE: config files with unrecognized keys now fail to load.
```

## Style (recommended, not required by the specification)

The specification only requires a short description. These habits keep history readable and pass
common linters:

- Imperative mood: "add", not "added" or "adds".
- Start the description with a lowercase letter and do not end it with a period.
- Keep the first line short (about 72 characters; `commitlint` defaults to a 100-character limit).
- Describe *what* changed in the description and *why* in the body. Wrap body lines at about 72 characters.

## Good vs. bad

| Bad                        | Good                                   |
|----------------------------|----------------------------------------|
| `fixed stuff`              | `fix(backup): correct total calculation` |
| `update`                   | `docs: add setup instructions` |
| `Added new login feature.` | `feat(identity): add two-factor login`     |
| `WIP`                      | `feat(restore): add basic filter UI`    |
| `feet: add export command` | `feat(cli): add export command`        |

## Commit size

The specification's advice is to make multiple commits whenever a change fits more than one type.
In practice, one commit is one logical change, not the fewest lines.

- One commit, one purpose. If the description needs "and", split it.
- Keep formatting, refactors, fixes, and features in separate commits.
- Each commit should leave the project working (build and tests pass).
- Commit tests together with the code they cover.
- Clean up noise like `fix typo` or `oops` commits before merging (`git rebase -i --autosquash`).
- Use `git add -p` to split mixed changes into separate commits.

## Squash merges

If pull requests are squash-merged, the pull request title becomes the commit subject. It must follow
this guide like any other commit message, and the squashed body and footers must too. The specification
recommends this workflow so maintainers can fix messages at merge time.

## No tool attribution

Authorship belongs to people, not tools. Commit messages must not mention code assistants or AI tools
in any form.

- Do not add `Co-authored-by:` or `Assisted-by:` trailers naming a tool.
- Do not list a tool as author or committer.
- Do not mention AI tools in the description, body, or footer.
- The person who commits is responsible for the change: they must understand it, review it, and be able to explain it.

Bad:

```
feat(cli): add pagination

Co-authored-by: <AI tool name>
```

Good:

```
feat(cli): add pagination
```

## Enforcement (optional)

- **Pull request titles** (best fit for a squash workflow), as a GitHub Actions job:

  ```yaml
  name: pr-title
  on:
    pull_request:
      types: [opened, edited, synchronize, reopened]
  permissions:
    pull-requests: read
  jobs:
    lint:
      runs-on: ubuntu-latest
      steps:
        - uses: amannn/action-semantic-pull-request@v5
          env:
            GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  ```

- **Local `commit-msg` hook:** run a commit linter such as `commitlint` with
  `@commitlint/config-conventional` through your hook manager (`lefthook`, `pre-commit`, or a plain
  `.git/hooks/commit-msg`).

## Quick checklist

- [ ] The prefix is `type[optional scope][!]: ` with a type from the table
- [ ] A description follows the colon and space immediately
- [ ] One logical change per commit, and the project still builds
- [ ] Body explains *why* (if needed)
- [ ] Breaking change marked with `!` and/or a `BREAKING CHANGE:` footer
- [ ] Related issue ID in a footer (if applicable)
- [ ] No tool or AI attribution anywhere in the message

## Optional: Git commit template

Save as `.gitmessage` and enable it with `git config commit.template .gitmessage`:

```
# <type>[optional scope][!]: <description>

# Body: explain why this change was made (wrap at about 72 chars)

# Footers: Refs: <issue-id>
# Breaking change: add ! before the colon and/or a "BREAKING CHANGE: <description>" footer

# Types: feat, fix, docs, style, refactor, perf, test, build, ci, chore, revert
```

## Reference

- Specification: https://www.conventionalcommits.org/en/v1.0.0/
- Git trailers: https://git-scm.com/docs/git-interpret-trailers
- Semantic Versioning: https://semver.org
