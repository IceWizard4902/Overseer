"""
These are all of the signatures related to using WMI
"""
from signatures.abstracts import Signature


class WMI(Signature):
    def __init__(self):
        super().__init__(
            name="wmi",
            description="JavaScript use Window Management Instrumentation",
            indicators=[".ExecQuery"]
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)