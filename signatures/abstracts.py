from typing import Any, Dict, List, Optional, Set, Union
from re import findall

ALL = "all"
ANY = "any"

class Signature: 
    """
    This Signature class represents an abstract signature which can be used for scoring and adding additional details
    to heuristics
    """

    def __init__(self, name: str = None, description: str = None, mbc: List[str] = None, indicators: List[str] = None, safelist: List[str] = None): 
        """
        This method instantiates the base Signature class and performs some validtion checks
        :param name: The name of the signature
        :param description: The description of the signature
        :param mbc: The MBC IDs of the signature
        :param indicators: A list of log_lines where each log_line is an indicator of behaviour that we should look out for
        :param safelist: The safelist that will contain log_lines that are considered "safe" and
        aim to prevent false positives
        """
        self.name: Optional[str] = name
        self.description: Optional[str] = description
        self.mbc: List[str] = [] if mbc is None else mbc
        self.indicators: List[str] = [] if indicators is None else indicators
        self.safelist: List[str] = [] if safelist is None else safelist
        
        # These are the lines of code from the sandbox that reflect when an indicator has been found
        self.marks: Set[str] = set()


    def check_indicators_in_list(self, output: List[str], match_all: bool = False) -> None:
        """
        This method takes a list of log_lines (output from MalwareJail) and looks for indicators in each line
        :param output: A list of log_lines where each log_line is a line of stdout from the MalwareJail tool
        :param match_all: All indicators must be found in a single line for a mark to be added
        """
        for log_line in output:
            # For more lines of output, there is a datetime separated by a -. We do not want the datetime.
            split_log_line = log_line.split(" - ")
            if len(split_log_line) == 2:
                log_line = split_log_line[1]

            # If we want to match all indicators in a line and nothing from the safelist is in that line, mark it!
            if match_all and all(indicator.lower() in log_line.lower() for indicator in self.indicators) and \
                    not any(item.lower() in log_line.lower() for item in self.safelist):
                self.marks.add(log_line)

            # If we only want to match at least one indicator in a line, then mark it!
            if not match_all:
                for indicator in self.indicators:
                    if indicator.lower() in log_line.lower() and \
                        not any(item.lower() in log_line.lower() for item in self.safelist):
                        self.marks.add(log_line)
                        continue

    @staticmethod
    def check_regex(regex: str, string: str) -> List[str]:
        """
        This method takes a string and looks for if the regex is able to find captures
        :param regex: A regular expression to be applied to the string
        :param string: A line of output
        """
        result = findall(regex, string)
        if len(result) > 0:
            return result
        else:
            return []

    def process_output(self, output: List[str]):
        """
        Each signature must override this method
        """
        raise NotImplementedError


    def add_mark(self, mark: Any) -> bool:
        """
        This method adds a mark to a list of marks, after making it safe
        :param mark: The mark to be added
        :return: A boolean indicating if the mark was added
        """
        if mark:
            self.marks.add(mark)
        else:
            return False

    def check_multiple_indicators_in_list(self, output: List[str], indicators: List[Dict[str, List[str]]]) -> None:
        """
        This method checks for multiple indicators in a list, with varying degrees of inclusivity
        :param output: A list of strings where each string is a line of stdout from the MalwareJail tool
        :param indicators: A list of dictionaries which represent indicators and how they should be matched
        :return: None
        """
        if not indicators:
            return

        all_indicators: List[Dict[str, Union[str, List[str]]]] = [indicator for indicator in indicators if indicator["method"] == ALL]
        any_indicators: List[Dict[str, Union[str, List[str]]]] = [indicator for indicator in indicators if indicator["method"] == ANY]

        for log_line in output:
            # For more lines of output, there is a datetime separated by a -. We do not want the datetime.
            split_line = log_line.split(" - ")
            if len(split_line) == 2:
                log_line = split_line[1]

            # If all_indicators
            are_indicators_matched = True
            for all_indicator in all_indicators:
                if are_indicators_matched and all(indicator in log_line for indicator in all_indicator["indicators"]):
                    for any_indicator in any_indicators:
                        if are_indicators_matched and any(indicator in log_line for indicator in any_indicator["indicators"]):
                            pass
                        else:
                            are_indicators_matched = False
                else:
                    are_indicators_matched = False

            # If no all_indicators
            if not all_indicators:
                for any_indicator in any_indicators:
                    if are_indicators_matched and any(indicator in log_line for indicator in any_indicator["indicators"]):
                        pass
                    else:
                        are_indicators_matched = False

            if are_indicators_matched and not any(item.lower() in log_line.lower() for item in self.safelist):
                self.marks.add(log_line)