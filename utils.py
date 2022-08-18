import os 
import pathlib

GREEN = "\033[32m"
BOLD = "\033[1m"
BLUE = "\033[94m"
RED = "\033[91m"
END = "\033[0m"

def display_banner():
    print(BLUE + """
   ___                              
  / _ \__ _____ _ _ ___ ___ ___ _ _ 
 | (_) \ V / -_) '_(_-</ -_) -_) '_|
  \___/ \_/\___|_| /__/\___\___|_|
        Author: @qvinhprolol 
        """ + END)

def display_log_green(phase, log):
  print(GREEN + BOLD + "[+] " + phase + END + ": " + log)

def display_log_blue(phase, log):
  print(BLUE + BOLD + "[+] " + phase + END + ": " + log)

def display_log_red(phase, log):
  print(RED + BOLD + "[+] " + phase + END + ": " + log)

def display_verdict(verdict):
  print(RED + BOLD + verdict)

def parse_bool(args):
  if args.lower() == "true":
    return True 
  elif args.lower() == "false":
    return False  
  else:
    return "Illegal"
