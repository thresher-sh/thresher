# Agents

Agents serve several roles in the repo. 

1. Discovery
2. Planning
3. Rationalizing
4. Formatting information to return

## Why Agents?

We want to use agents to do non-deterministic work. To discover and look and peek. To use tools and get unexpected results.

It's easier to ask an agent to explore and bring answers than to write a perfect script that explores and finds everything every time.

## Discovery

Types of discovery we care about:

1. Dependencies. So predependency agent looks through files and finds stuff like git clones, package manager files, blob downloads, docker downloads, etc... Helps build things that we can then pass to a resolver script to download stuff.
2. Maliciousness. Analysts look for malicious code doing bad things that would harm us.
3. App discovery. Looking for things bad in the app and quality issues.

## Planning

Because discovery is being done by agents, the adversarial agent may do things differently based on the plans from the 8 analysts.

## Rationalizing

Looking at things, figuring out if actually issues, doing web searches on it, etc.. Agents are able to do. Especially adversarial and synthesis agent.

## Formatting

Goal is report agent is able to generically build outputs that look well and are well formatted for reports.


# Analyst Agents

The analysts (at this time 8 of them) are specific personas that are charged with answering high level open ended questions about the target repository. They should cover several angles and because of the [agent isolation](./agent-isolation.md) they should be focused on their job only and no distractions.

Number of analysts are defined by the numbered yaml configs under agents/definitions

# Agent configs

All agents are configured by yaml files in agents/definitions. Should include prompts, model configs, etc...

# Other details

Some more details in the agent isolation doc