# Harness

The idea of the harness is the pipeline and all the modules and scripts that execute the full scan.

It's python, uses hamilton for now (we may change this later to something else).

The harness currently orchestrates a set of subprocess runs via thresher.run.run().

Those runs could invoke:

- Claude Code as an agent
- Some scanner util


## Agents

[Agents](./agents.md) are claude code run in headless mode atm. But we plan to expand this to an agent factory that can use any agent harness like opencode or droid or something...

## Scanners

[Scanners](./scanners.md) are CLI tools. We typically just call them in sequence and through subprocess calls.

## Pipeline

The [pipeline](./pipeline.md) right now is hamilton, but likely will change to something else later cause I don't like how it defines its DAG...