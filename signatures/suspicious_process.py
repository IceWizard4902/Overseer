"""
These are all of the signatures related to the precense of suspicious processes
"""
from signatures.abstracts import Signature


class SuspiciousProcess(Signature):
    def __init__(self):
        super().__init__(
            name="suspicious_process",
            description="JavaScript uses a suspicious process",
            indicators=["winmgmts", "eval(", "uneval("]
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)