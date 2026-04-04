# v0.3.0

## Benchmarks

- Tokens In
- Tokens Out
- Tool Calls
- Runtime
etc...

So we can calculate costs etc and impact and average cost to run them, then build configurations for max turns etc into the thresher.toml file so folks can tune to what they want to pay...

## Docker for app

Move everything into a dockerfile for provisioning.

1. Build Dockerfile
    - On builds pin to hash, validate checksums on things like YARA clone
2. Launch Lima Container, with docker image
3. Phase 1: Execute docker to git clone and find dependencies
4. Phase 2: Execute docker to resolve dependencies (Isolates blast radius for local runs)
5. Phase 3: Execute docker to run tools
6. Phase 4: Execute docker to run AI Analysts
7. Phase 5: Copy reports out

v0.4.0 will do one docker execution in the cloud. The VM is our "cloud" at this point.

## Scan Targets

- Add local folder support
- Add local git support
- Add gitlab support

> In general we need to also update from shallow git clones to full clones... shallow clones reduce our forensic ability.

## Tool Improvements

1. Reachability analysis (Semgrep claims 98% false positive reduction, Endor Labs uses it for "95% fewer alerts") — determine if adversarial verification achieves similar noise reduction, quantify it.
2. Add tooling to detect and decrypt https://github.com/elder-plinius/st3gg
3. Update semgrep rules.
4. Update malware scanning tools and dbs
5. More secret scanning
6. Sonarqube style scanning
7. Snyk style scanning

## AI Analyst Improvements

1. Review prompts
2. Introduce QA Analyst
3. Update Activity Risk Analyst - Repo bus factor, popularity, etc.. 
4. Add scans (Either deterministic tools or Analysts) that target issues seen in LiteLLM and Axios Hack.

## Results an Reports

1. Improve Reports and Results formating.
    - Add styled report.html output
    - Self-contained single HTML file matching website aesthetic
    - Include scanner findings, AI analyst findings, adversarial results, synthesis
    - Can be opened locally or hosted
    - Based on the showcase report.html we're building for the website already
2. Test against 20x known popular and friendly repos, submit PRs based on findings to build body of evidence.

### v0.2.0 Validation

Test reports against 5x projects with v0.2.0 and validate results/outputs. Open PRs.

1. Did it use the tools given to the agents correclty
2. Did we get output reports from all agents
3. Any tool errors on our 22 scans?
4. Are we consistent on fresh base rebuilds and scan?
5. Is build from scan working?
6. Validate export
7. Validate import
