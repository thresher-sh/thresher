# Dependency Resolution


3 Phases

1. Agentic Discovery
2. Static Discovery
3. Dependency Resolution (Downloads)


## Agentic discovery

Agent runs and looks through all data and files in the target repo.

Identifies the following generally:

1. List of package manager files
2. list of dependencies
3. list of hidden dependencies
4. list of file downloads etc

Hidden dependencies may be things hidden in dockerfiles, shell scripts, vm images, etc....

## Static Discovery

Quick scan for things like package.json, requirements.txt, pyproject.toml, etc...

## Dependency Resolution

Taking all the discovered dependencies from the agent and the static view, download everything into `/opt/deps` and `/opt/target`. Fully resolve dependencies and download binaries etc that are not high risk.

This should handle all ecosystems and download types. Simple right now, but in v4 we plan to make this extendable and targeted modules for each dependency type.

Some high-risk may download if thresher was passed with its high-risk download flag