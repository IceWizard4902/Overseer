"""
These are all of the signatures related to hiding malicious behaviour
"""
from signatures.abstracts import Signature


class HideObjects(Signature):
    def __init__(self):
        super().__init__(
            name="hide_object",
            description="JavaScript removes objects that were recently appended",
            indicators=["document.body.appendChild(", "document.body.removeChild("]
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)