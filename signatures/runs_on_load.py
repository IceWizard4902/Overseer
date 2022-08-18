"""
These are all of the signatures related to running a document object on page load
"""
from signatures.abstracts import Signature


class AppendAndClick(Signature):
    def __init__(self):
        super().__init__(
            name="append_and_click",
            description="JavaScript appends a child object to the document and clicks it",
            indicators=["document.body.appendChild(", ".click("]
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)