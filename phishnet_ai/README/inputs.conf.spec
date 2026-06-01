#
# PhishNet AI - inputs.conf.spec
# Schema for the phishnet_agent modular input.
#

[phishnet_agent://<name>]
source_index = <string>
* The Splunk index the agent reads incoming phishing alerts from.
* Default: phishing

actions_index = <string>
* The index the agent writes investigation reports to.
* Default: phishnet_actions

metrics_index = <string>
* The index containing endpoint/host metrics used for Blast Radius correlation.
* Default: metrics

mode = recommend|auto
* recommend: the agent recommends actions; an analyst must confirm before closure.
* auto: the agent auto-closes high-confidence false positives (use with care).
* Default: recommend

classifier = dsdl|huggingface|mock
* dsdl: classify via the Foundation-Sec-8B DSDL container endpoint.
* huggingface: classify via a locally loaded Foundation-Sec-8B model.
* mock: deterministic stub classifier for development and demos.
* Default: mock
