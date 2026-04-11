# Agents structured output

Agents are forced into structured json output and specific json schemas by utilizing stop hooks on claude code.

If you look at agents/hooks you will see scripts that are run on the stop hook for each agent. Those scripts validate the output and force it to redo if it fails the expected json output.

Any fixes to json parsing, output etc, should be done in these stop hooks as they are the source of validation.