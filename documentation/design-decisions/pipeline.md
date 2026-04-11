# Pipeline

Current pipeline is generally as follows

clone -> find dependencies -> resolve dependencies -> run scanners -> run analysts -> adversarial review -> enhance_cve -> synthesis -> report

The DAG will fan out for scanners and analysts and run those in parallel.

## Outputs

Each stage should output its data to disk immediately after it runs. Right now it does, but we will fix that in v4.

## The brain

The pipeline is the brain of the system, it's what is making sure everything goes as planned. Eventually the pipeline may be replaced by an orchestrator agent, but for now it's static with agents running underneath it.