# Issue tracker: GitHub

Issues and specs live as GitHub issues on this repo, tracked on its GitHub Projects board. Use the `gh` CLI.

- **Create**: `gh issue create --title "..." --body-file <file>`
- **Read**: `gh issue view <number> --json number,title,body,labels,comments`
- **Sub-issue**: `gh issue create --parent <parent> ...`
- **Blocking**: `gh issue create --blocked-by <n>,<n> ...` or `gh issue edit <child> --add-blocked-by <blocker>`
- **Close**: comment with the commit, then `gh issue close <number>`, and set the board item to Done.

**PRs as a request surface: no.**

This repo is public. Never paste report or log contents into issues.
