# Testing

AI is both good and bad at tests... to combat this we do a few things.

1. we ask it to write tests for every feature.
2. we ask it to write tests before the feature exists, and they should break and then pass once the feature exists (TDD)
3. anytime we give an error we ask it to add tests to cover that edge case

Mostly are unit tests, and manual runs of scans to get integration/functional tests.

I want to expand one off integration/functional tests with real claude code calls etc... but $$$ be $$$...