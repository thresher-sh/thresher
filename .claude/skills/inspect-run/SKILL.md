---
name: inspect-run
description: Use when looking at a run to make sure outputs are what we expect, and things are going well
---

# Inputs

Run ID: Id of the run, corresponds to folder in ./thresher-reports and ./logs

# Process

This is a multi agent subflow.

For each scanner and each ai agent launch a subagent to do the following:

- Look at scanner/agent results
    - Look for any issues
    - Validate outcomes
- Look at logs for that scanners/agents outputs and invocations
    - Did the scanner/agent run
    - Any errors or warnings
    - Did the scanner/agent finish
    - Any surprises?
    - For agents in particular. Validate that the # of turns it took is equal to the # of turns allowed max in config.

Then look at the report summaries:

- Are all expected outputs there that are defined in docsc/code?
- Are any of the findings unexpecitly missing or empty?
- Summaries have AI report in them, and are not missing (Unless ran in --skip-ai) mode.

Any anomolies identify the root cause.

Finally look for any missing artifacts. All analyst findings and summaries are in the scan-results folder? All scanner results are in scan results folder and no corrupted? All files in root report folder are there like summaries and reports and deduped findings? the html report is there? 


Generate a report whith CRITICAL/HIGH/MEDIUM/LOW issues.

- What it is
- Whats observed
- What was expected
- What potential areas to look at or potential reasons for bug

Generate a list at end of report of unit tests that if they existed today would fail because of these findings. And then think of any additional unit tests we should ad on edge cases around these areas that we wouldn't have thought of otherwise.

Write the report to a file.