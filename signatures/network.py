"""
These are all of the signatures related to making network requests
"""
from signatures.abstracts import Signature


class PrepareNetworkRequest(Signature):
    def __init__(self):
        super().__init__(
            name="prepare_network_request",
            description="JavaScript prepares a network request",
            indicators=[".setRequestHeader(", "User-Agent", "XMLHttpRequest(", "URL.createObjectURL("]
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)


class NetworkRequest(Signature):
    def __init__(self):
        super().__init__(
            name="network_request",
            description="JavaScript sends a network request",
            indicators=[".send()"]
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)