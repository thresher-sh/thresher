# Cloud Testing

Simple plan for testing this in cloud against real infected packages...

Provider:
- https://www.macincloud.com/
- https://aws.amazon.com/ec2/instance-types/mac/
- https://macstadium.com/


1. Provision SSH Keys/API keys needed with scope
2. Spin up from base clean image.
3. Execute tests.
4. Validate.
5. Destroy vm/image.
6. Destroy provisioned SSH and API keys. Consider them compromised.

## API's and Services should be setup with unrelated email information

Because if something goes wrong we want to set blast radius, so just use a new gmail account create claude account and use it for testing vs personal so if hijacked for some reason because I fail at security then it limits blast radius to just that set of credentials.

## Why

Allows testing known vulnerabilities and vm guardrails and isolation mechanisms in safe lab. 

Able to clean up quickly and compeltely, start fresh each time.

Prevents any access to systems on same network as me, ip routes, etc..

Can test real world scenarios.