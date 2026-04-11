# Benchmarks

Simple stats on each node in the graph.

## Non-agentic

1. Runtime
2. Count of findings
3. # of errors

## Agentic

1. Runtime
2. Count of findings
3. Token counts
    a. tokens in
    b. tokens out
    c. tokens write cache
    d. tokens read cache
4. # of errors


# Sum

At end of pipeline a cost report is created. 

Costs stored in `./src/thresher/report/data/costs_claude.json`. 

Report is:

1. Each stage of pipeline... Each Agent
2. Individual stats for that stage/agent
3. Total stats for all "analysts"
4. Total stats for entire pipeline

Report is saved as json and markdown.