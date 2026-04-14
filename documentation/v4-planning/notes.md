# v0.4.0 Planning

v0.4.0 is a big change to operating model...

## Docker Primary

v0.3.0 took steps towards this with docker in lima... in v0.4.0 the docker image is the primary distributable and the application becomes orchestration of that against either lima vm, remote location, or directly executing the docker container (Like CICD). In 0.4.0 there is no build step, as build is done once and everyone one uses same docker image.

Right now we are spinning up a VM and orchestrating into it etc... V3 instead operates as one bundle that expects it is running inside a secure environment... It lowers complexity and orchestrates everything locally. 

- On a mac or linux machine with hypervisor etc, that means we launch lima vm and run the application completely within the lima vm, and then we stream out the reports... But this will not be the recommended or default way to run.
- On a cloud server, we don't launch a vm and we just run the application. the new `--no-vm` flag will ignore lima wrapper and just execute. 

## Remote Runner
We will introduce a remote runner version. This takes the application and points to a configured provider such as AWS, GCP, Digital Ocean, Azure, etc and launches a container in that system, runs the scan, extracts the report, and then shuts down the container. Allowing you the most flexibility for manual scans.

Remote runner will become the default way to run the application, with lima as the secondary for people who do not have access to a cloud platform to execute on.

### Upload Target

in v0.3.0 we introduced local targets (Git / folders)... In v0.4.0 remote runners we will support uploading local targets to the remote container.

## CICD
This setup allows us to support CICD runs for automatic detection on triggers like PRs etc.

## Ephemeral Credentials
As part of this it will be recommended and default to use ephemeral credentials for two things:

1. Git access for private repo access. The system will create a read only deploy key for the target repository, if unable to do that it will walk through creating a short lived access token.
2. AI Model access via virtual keys. Openrouter or LiteLLM or similar support generating keys with a management key. So the app will automatically provision a key, launch the scan, and destroy the key. 

The assumption is that any scan compromises any key in that environment. Hence the need for ephemeral keys.

## Support other models / harnesses

We started with claude code. We support other models and harnesses on this release. The main ways are:

1. Proxy Host for Claude Code. Use CC with openrouter or litellm models vs Anthropic Key
2. Swap harness all together with pi.dev, open code, etc...

For this we will need model and harness factories based on configuration to load.

## Explore Skill based orchestration

Right now we manually execute our orchestration, explore just using a skill and letting the harness figure it out... Extremely exploratory...
Likely move this to v0.5.0

## Todo Features

1. Add `--no-vm` flag to not use lima vm isolation. Used for running in contianers, functions, etc...
2. Add support for codex, pi.dev, opencode, Droid, Openclaw, forgecode
3. Add support for AI Gateways (openrouter, litellm, together.ai, tenzorzero)
4. Docker Container (runs in `--no-vm` mode) (Solve docker in docker for scanning docker dependencies, optional addon later)
    - Github Action Support
    - Remote Runner Support (DO Functions, Lambda, GCP Functions)
    - secute on demand GCP, AWS, Azure, DO, etc...

