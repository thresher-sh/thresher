Snapshot and confirm SHA Checksums of dependencies we are downloading and installing. 

For example YARA git clone... pin itt.

---

Move agents and the like from this command and control stuff to agent code and shell commands are all scripts deployed into VM, vs the outside in orchestration it is now. I don't like what it is doing atm, but will come back and fix it later...

---

Move final report copy to a text only stream of report data, no actual file copies.


---

Validate these things from github issue todo:
    Validate clamav db is up to date in target image.
    more secret scanning
    Pentester persona for analysis (can target oss package be exploited if pulled into system)
    Additional sonarqube/snyk analysis type stuff (Static code analysis for quality)
    General pattern, quality checker
    Activitiy/Risk checker - Popularity, last pushed change, maintainer activities, # of stale pull requests, etc...
    Commit history, recently (any new packages added? How old are those packages?)
    Scan for remote downloads hidden within special tools like the axios hack



---

AI Benchmark
- Tokens In
- Tokens Out
- Tool Calls
- Runtime
etc...

So we can calculate costs etc and impact and average cost to run them, then build configurations for max turns etc into the thresher.toml file so folks can tune to what they want to pay...


----

Shallow git clone breaks forensic abilities


-----

Figure out safe way to proxy git ssh token to access private repositories...
Add in local git access


---

Website: report.html as scan output
- Add styled report.html generation as an output of thresher scan
- Self-contained single HTML file matching website aesthetic
- Include scanner findings, AI analyst findings, adversarial results, synthesis
- Can be opened locally or hosted
- Based on the showcase report.html we're building for the website

---

Competitor feature gaps (from website research, April 2026):

1. Reachability analysis (Semgrep claims 98% false positive reduction,
   Endor Labs uses it for "95% fewer alerts") — determine if adversarial
   verification achieves similar noise reduction, quantify it

2. IDE integration (Semgrep has IDE + MCP server, Snyk has IDE plugins)
   — consider VS Code extension or MCP server for thresher

3. CI/CD integration (all competitors emphasize PR-level blocking)
   — GitHub Action for thresher scan on PR

4. Demo video (Snyk has embedded video on homepage)
   — record a terminal screencast of a real scan

5. ROI / metrics storytelling (Snyk leads with "288% ROI", "80% faster")
   — quantify scan depth vs competitors (22 scanners vs typical 1-3)