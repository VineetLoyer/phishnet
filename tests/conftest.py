"""Test session setup.

The smoke tests are designed to run fully offline (file backend, mock
classifier). Strip any ambient PHISHNET_SPLUNK_* credentials so AgentConfig
doesn't pick them up and reach out to a live Splunk (KV cache, etc.) mid-test.
"""

import os

for _var in ("PHISHNET_SPLUNK_USER", "PHISHNET_SPLUNK_PW", "PHISHNET_SPLUNK_TOKEN"):
    os.environ.pop(_var, None)
