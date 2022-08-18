"""
These are all of the signatures related to gathering information about the environment
"""
from signatures.abstracts import Signature


class ExpandEnvStrings(Signature):
    def __init__(self):
        super().__init__(
            name="env_str_recon",
            description="JavaScript looks at the environment strings",
            indicators=[".ExpandEnvironmentStrings"]
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)


class DriveObject(Signature):
    def __init__(self):
        super().__init__(
            name="drive_object",
            description="JavaScript creates an object representing a hard drive",
            indicators=["DriveObject"]
        )

    def process_output(self, output):
        self.check_indicators_in_list(output)


class FileSystemObject(Signature):
    def __init__(self):
        super().__init__(
            name="file_system_object",
            description="JavaScript creates an ActiveXObject to gain access to the computer's file system",
            indicators=["Scripting.FileSystemObject"]
        )

    def process_output(self, output):
        self.check_indicators_in_list(output, match_all=True)