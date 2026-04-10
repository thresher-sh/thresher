# Report Maker

A consitent generator of highly styled and awesome reports.. Using the @report_maker/example_report.html as a guideline...

We will do the following things together:

1. Convert the existing example report to a react powered page, that inline renders (no build process just open the html page and it looks good)
2. Convert all areas of "data" or "informed" stuff to have react placeholders that load from a json structure.
3. Add at bottom of the html in the <script></script> section the inline json that populates the react page.
4. Do this and generate example_react_report.html that when viewed is exactly the same as example_report.html except everything is data driven by that json file -> react.
5. Generate a json schema that enforces the json structure needed in the react version.
6. Generate a template_report.html that is the example_react_report.html just that the area of the json is a jinja placeholder. (So we can inject the json in at compile time).
6. Create a claude code setup for headless mode that would:
    a. read and understand the the example_react_report.html
    b. read and undestand the json schema.
    c. read a vulerability scan report folder.
    d. create and return json that would fit for the report.
    e. on stop hook, a validate_json_output.sh would fire to use the json schema we have to validate the output of the agent.
7. A python function that takes the headless mode output, uses jinja to insert it into the template and outputs a report.html

### Requirements

1. The above criteria
2. The report must be maintained in visual hierarchy and functionality
3. The report must be visually appealing and amazing.
4. The json values are all strings, so there are no render issues on the page.
5. Optionally some json areas like "EXECUTIVE SUMMARY" may accept inline jsx or html ... This is to allow great dynamic data for the executive summary like what is present in the example_report.html and so we don't get a vauge one paragraph answer.
6. When null values are present, or low amount of findings are there, the template should still render beautiful report.
7. Remediation data would not be present on first pass, we would need a follow up run where we pass in a PR report in to update it. So our pipeline here would not fill out that section yet. (But we should design the section, placeholder values, etc and just hide it for now...) ... [However... you should put a toggle in the javacript to show/hide so I can test what it would look like if visibile to validate the report output].