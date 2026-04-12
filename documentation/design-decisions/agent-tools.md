# Agent Tools

Outside the standard agentic tools for read, write, bash, webfetch etc...

We have also set up tools for agents to use in their investigations. These are security related tools, and agents use them to inspect and poke/prod the target repo.

They can invoke them as bash commands, and it's completely up to them how they use them. We just let them know they are there.

Tools:

- ast-grep
- tree-sitter
- semgrep
- bandit
- checkov
- guarddog
- scancode-toolkit
- govulncheck
- cargo-audit
- syft
- grype
- trivy
- gitleaks
- osv-scanner
- hadolint
- clamav
- yara
- shellcheck
- binwalk
- exiftool
- objdump
- readelf
- nm
- ldd
- size
- strings
- xxd
- od
- file
- base64
- openssl
- diff
- jq
- cloc
- git (log, blame, shortlog, reflog, fsck)
- curl
- wget
- python3
- node
- go
- cargo

## Agents Harness Tools

Before we started with a restricted set of tools. But agents are running inside a container so we can let them roam a bit more free. 

All agents should have access to:

- read
- write
- edit
- bash
- webfetch
- websearch