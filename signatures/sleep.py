"""
These are all of the signatures related to causing execution to delay
"""
from signatures.abstracts import Signature


class Sleep(Signature):
    def __init__(self):
        super().__init__(
            name="sleep",
            description="JavaScript attempts to sleep",
            indicators=["WScript.Sleep", ".setTimeout("]
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)
        if len(self.marks) > 10:
            self.marks = set(list(self.marks)[:10])


class AntiSandboxTimeout(Signature):
    def __init__(self):
        super().__init__(
            name="antisandbox_timeout",
            description="JavaScript file managed to delay execution until the sandbox timed out",
            indicators=["Script execution timed out after"]
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)