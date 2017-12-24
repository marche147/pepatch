
from __future__ import print_function
import colorama

colorama.init()
YELLOW = colorama.Fore.YELLOW
RED = colorama.Fore.RED
GREEN = colorama.Fore.GREEN
BLUE = colorama.Fore.LIGHTBLUE_EX
WHITE = colorama.Fore.WHITE

def warn(msg):
    print("[" + YELLOW + 'WARN' + WHITE + '] ' + msg)
    return

def info(msg):
    print("[" + BLUE + 'INFO' + WHITE + '] ' + msg)
    return

def success(msg):
    print("[" + GREEN + 'GOOD' + WHITE + '] ' + msg)
    return

def error(msg):
    print("[" + RED + 'FAIL' + WHITE + '] ' + msg)
    return

__all__ = ['warn', 'info', 'success', 'error']
