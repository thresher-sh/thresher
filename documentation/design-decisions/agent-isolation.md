# agent isolation

Goal is simply that agents run independent of each other in their own worktrees. 

They should have context of only the dependencies they know about and the target repo.

They should not have context of the scanners unless specifically given. For example the 8 analysts should not have access to scanner outputs as we do not want to poison their context.

Adversarial agent doesn't have scanner outputs either and just analyst inputs.

Synthesis sees all outputs.


Current agents and access should be:

## Predep

- goal = search repo for all dependencies and downloads including ones nested and hidden in folders, dockerfiles, shell scripts, etc...
- Input = target folder
- Output = hidden_deps.json (But really it is all dependency downloads)


## Analysts x8

- goal = individual analysts (8 of them) that look at the repo and answer a specific open ended question, and are expected to inspect deeply the repo for answers and even look under unturned stones.
- Input = target folder, dependencies downloaded by the dependency resolver stage
- Output = findings.json, summary.md

# Adversarial Agent

- goal = review outputs from agents, and adversarially review them. Raise issues, lower issues, find out if things are false positives or real threats/issues.
- input = analyst findings.json's, analysts summary.md's
- output = findings.json, summary.md

# Synthesis Agent

- goal = look at everything and build details for executive and detailed report as well as its own synthesis finding.
- input = scanner outputs, analyst outputs, adversarial outputs
- output = synthesis summary, details for exec and detailed summary

# Report agent

- goal = take all the information currently available + lean on the detailed summary output as primary anchor. Generate json to populate the report template.
- input = detailed-report.md, executive-summary.md, example report templates, example json schemas etc...
- output = report.json (that gets injected into report.html)