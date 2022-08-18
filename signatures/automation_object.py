"""
These are all of the signatures related to using the AutomationObject
"""
from signatures.abstracts import Signature


class AutomationObject(Signature):
    def __init__(self):
        super().__init__(
            name="auto_object",
            description="JavaScript creates an AutomationObject",
            indicators=["AutomationObject"]
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)


class WinMgmtsAutoObject(Signature):
    def __init__(self):
        super().__init__(
            name="auto_object_winmgmts",
            description="JavaScript creates an AutomationObject that uses winmgmts",
            indicators=["AutomationObject", "winmgmts"]
        )

    def process_output(self, output):
        self.check_indicators_in_list(output, match_all=True)