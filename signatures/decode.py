"""
These are all of the signatures related to decoding
"""
from signatures.abstracts import Signature


class Unescape(Signature):
    def __init__(self):
        super().__init__(
            name="unescape",
            description="JavaScript uses unescape() to decode an encoded string",
            indicators=["unescape"]
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)


class SuspiciousUseOfCharCodes(Signature):
    def __init__(self):
        super().__init__(
            name="suspicious_char_codes",
            description="JavaScript uses charCodeAt() obfuscate/de-obfuscate characters",
            indicators=[".charCodeAt("]
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)