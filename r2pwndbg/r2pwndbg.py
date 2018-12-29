#!/usr/bin/env python3

import r2pipe
import sys
import signal

def generate_known_cmd(cmd):
    return [cmd[:i] for i in range(1, len(cmd) + 1)]

known_cmds = {
    "file": ["file"],
    "continue": generate_known_cmd("continue"),
    "step": generate_known_cmd("step"),
    "info": generate_known_cmd("info"),
    "heap": generate_known_cmd("heap"),
    "context": ["context"],
    "exit": ["exit"],
    "quit": generate_known_cmd("quit")
}

is_known = lambda cmd, cmdset: cmd in known_cmds[cmdset]
p_red = lambda txt: "\033[91m{}\033[0m".format(txt)

class r2pwndbg:

    def __init__(self, filename=None):
        self.filename = filename
        self.lastcmd = None
        if filename != None:
            self.r2 = r2pipe.open(filename, flags=['-d', '-2'])


def main():

    if len(sys.argv) > 1:
        filename = sys.argv[1]
        r2 = r2pwndbg(filename)

    while True:
        cmd = input(p_red("r2pwndbg> ")).strip()
        cmd = cmd.split(" ", maxsplit=1)
        if len(cmd) == 1:
            cmd, args = cmd[0], None
        elif len(cmd) == 2:
            cmd, args = cmd[0], cmd[1]
        else:
            print("hmm...", file=sys.stderr)

        print("cmd: {}".format(cmd), file=sys.stderr)
        print("args: {}".format(args), file=sys.stderr)

        if is_known(cmd, "file"):
            print("file command")
        elif is_known(cmd, "continue"):
            print("continue command")
        elif is_known(cmd, "step"):
            print("step command")
        elif is_known(cmd, "info"):
            print("info command")
        elif is_known(cmd, "heap"):
            print("heap command")
        elif is_known(cmd, "context"):
            print("context command")
        elif is_known(cmd, "exit") or is_known(cmd, "quit"):
            exit(0)
        else:
            print("unknown command")



if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        exit(0)
    except EOFError:
        print("EOFError", file=sys.stderr)
        exit(1)