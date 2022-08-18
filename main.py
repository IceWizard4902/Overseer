from inspect import getmembers, isclass
from threading import Thread 

import argparse
import os
import signatures
import subprocess
import utils

from time import time
from pkgutil import iter_modules
from signatures.abstracts import Signature
from sys import modules
from typing import Any, Dict, List, Optional

def run_signatures(output: List[str]) -> None:
    """
    This method sets up the parallelized signature engine and runs each signature against the
    stdout from MalwareJail
    :param output: A list of strings where each string is a line of stdout from the MalwareJail tool
    :return: None
    """
    # Loading signatures
    sigs = []
    abstracts = "signatures.abstracts"
    signature_class = "Signature"
    for _, modname, _ in iter_modules(signatures.__path__, f"{signatures.__name__}."):
        if modname == abstracts:
            continue
        __import__(modname)
        clsmembers = getmembers(modules[modname], isclass)
        for cls in clsmembers:
            name, obj = cls
            if name == signature_class:
                continue
            sigs.append(obj())

    # Running signatures
    signatures_that_hit = []
    sig_threads = []

    utils.display_log_blue("Overseer",f"Running {len(sigs)} signatures...")
    start_time = time()
    for sig in sigs:
        thr = Thread(target=_process_signature, args=(sig, output, signatures_that_hit))
        sig_threads.append(thr)
        thr.start()

    for thread in sig_threads:
        thread.join()
    utils.display_log_blue("Overseer", f"Completed running {len(sigs)} signatures! Time elapsed: {round(time() - start_time)}s")

    # Adding signatures to results
    if len(signatures_that_hit) > 0:
        for sig_that_hit in signatures_that_hit:
            utils.display_log_red("Malware", sig_that_hit.description)
            for mark in sig_that_hit.marks:
                print(output.index(mark))


def _process_signature(signature: Signature, output: List[str], signatures_that_hit: List[Signature]) -> None:
    """
    This method is used for the purpose of multi-threading and sharing the signatures_that_hit list
    :param signature: A Signature object that represents a signature
    :param output: A list of strings where each string is a line of stdout from the MalwareJail tool
    :param signatures_that_hit: A list containing all signatures that hit
    :return: None
    """
    signature.process_output(output)
    if len(signature.marks) > 0:
        signatures_that_hit.append(signature)

def main():
	utils.display_banner()
	
	parser = argparse.ArgumentParser(description='Analyzing malware behavior of stage-n malware')
	parser.add_argument('-t', '--target', type=str, help='Path to malware file, specify full path')
	parser.add_argument('-o', '--output', type=str, default="malware-jail/output", help='Path to malware artifacts directory, specify full path')
	args = parser.parse_args()
	
	# If output folder does not exist
	if not os.path.isdir(args.output):
		os.mkdir(args.output)

	# Prepare output file and running the tool 
	output_file = "output.txt"
	log_file = open(output_file, "w")
	current_directory = os.getcwd()
	os.chdir("malware-jail")

	# Running malware-jail
	start_time = time()
	utils.display_log_green("malware-jail", "Analyzing malware at " + args.target)
	malware_jail_args = ["node", "jailme.js", args.target, "-s", args.output + "/"]
	subprocess.run(malware_jail_args, stdout=log_file)
	log_file.close()

	# Logging 
	utils.display_log_green("malware-jail", f"Completed running! Time elapsed: {round(time() - start_time)}s")
	utils.display_log_green("malware-jail", "Malware artifacts folder at " + args.output)
	utils.display_log_green("malware-jail", "Running log is saved in " + output_file)

	# Opening log file for signature analysis
	log_file = open(current_directory + "/" + output_file, "r")
	lines = log_file.readlines()
	lines = [line.rstrip() for line in lines]
	log_file.close()

	run_signatures(lines)
if __name__ == "__main__":
	main()