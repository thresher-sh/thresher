# Agent Structured Response

We want certain defined outputs from agents, and different providers/harnesses have different strategies.

## Agent Ouput is unreliable

If we just ask the agent to output results, sometimes it writes a file, sometimes it returns result but wrapped in code fences and summary details. 

It's unreliable to just ask it to return.

## Some agents support structured output

If an agent harness or library supports structured output, we can just use that. But often this isn't directly supported or it is under certain use cases.

## Stop hooks cause long turn cycles

A lot of harnesses have stop hooks you can fire a script on after it finishes. This is a solid way to ensure output. However, there is one drawback... It forces multiple rounds of the agent "trying" to get it right. This may cause it to take longer or exhaust turn counts. I've seen it add 20+ minutes before.

## MCP Tools seem good

I've had better luck providing an MCP server that has a submit_result tool, and asking it to use that when it's done. Most agent harnesses are good these days at calling MCP server tools... so it makes sense.

(This is our planned strategy)


# Structure

we use JSONSCHEMA to validate structure if on a stop hook, if through MCP tool call it's validated on the call itself. MCP tools give schema to call the tool.