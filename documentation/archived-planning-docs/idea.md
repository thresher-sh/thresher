# Project Threat Scanner Spec

Open source projects are really cool, but they can often include tons of chains of open source projects within their dependencies. Any one of these systems plus that open source system is vulnerable to an attack in the supply chain of those packages.

So how do we prevent that? Well, there's lots of tools out there, but the AI models are getting better and better, especially harnesses. I'm going to build this project to utilize Claude Code for starters, but I'm open to other harnesses in the future to scan and process against open source systems.

However, we inherently will not trust this code, so we need a safe environment to test this. Docker is not good because we won't be able to use any Docker stuff to do scanning or pull down containers or run Docker compose or any of that kind of stuff.

So instead, I would like to use Vagrant virtual box type stuff with some command line utilities to spin up an environment, pull down a target repo in that environment, and then run a Claude code instance to achieve our desired outcome.

The Claude Code instance should be interactive. When we launch this system, it would launch into that Claude Code, and then we can initiate the skills, etc., that we want from there. Or we can programmatically run it and let it just run in the background until complete.

Reports and stuff should be saved within the running VM system. Nothing should be returned out of the VM back to the host system, because we don't want any bindings. Instead, we want all reports and stuff saved within the VM, which then we can interact with via SSH to pull anything back or whatever we want to our host machine safely.

We also want to include any kind of open source security scanning software, etc., that can do static analysis or look at known existing CVEs and stuff for this, so we want to do some research for that.

There's also a bunch of projects out there, like OpenClaw, etc., that have started looking at the automation of the Claude Code and the agent harnesses and stuff to make sure that they're doing things on heartbeats or continually working until the problem is solved. We don't want to just run a single prompt here and expect a good outcome. We want to run an orchestration of several sub-agents within this Claude Code instance using skills, etc., to build a robust adversarial team to look at the system, scan it, analyze it, size it, do analysis of it, and build a robust risk report.

All code has risk, but we need to know at what level of risk (low to critical) this has, and specifically what can go wrong.

Recent big things that have gone wrong are like the LiteLLM package had a supply chain where somebody injected malware. Even at just the import of that package, not even executing the package, just importing it into a project would run it and steal all the secrets and keys off a machine.

I strongly believe that AI can search and find these vulnerabilities easily.

So we need to do research, and then we need to build the system that allows us to run a Vagrant VM. I'm open to Firecracker and other stuff, but I do need to run this from a MacBook, from macOS, not from a different type of machine.


===> This was sent to claude.ai opus deep research to build some planning and discovery. 