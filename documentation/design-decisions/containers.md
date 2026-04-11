# Containers

We have containers and we have vms.

VMs offer more kernel level security and isolation. And in production local usage, you should be using the VM + Docker model.

Currently we use lima for the VM, maybe we will keep it. But we are looking at some VMMs like microsandbox and running our docker image as an OCI vmm image. We get kernel isolation and the container runtime in one whack.

Docker container is mostly for fast development and deployment of our custom tools, configs, and folder development.

We can easily do quick docker builds locally and in CI with cached layers, while VM provisions and image building take much longer and are much more complex.

## Local Dev

Almost always run local dev with --docker. There is a non-vm option but you need to have your environment set up perfectly to do that... It's much easier to run the --docker bit.

## Layers

Host => VM Kernel => Docker Image

## Credentials

One benefit of using something like microsandbox is the credential bit. Right now we have to inject credentials into the VM for them to be available.

With MSB we can host credentials outside the VM and have only placeholders used inside the machine. I'm sure this will take lots of testing but I think it allows us to do things like pass git credentials for private repo access without compromising or exposing those credentials to something that goes into the VM kernel.