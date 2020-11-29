import cmd

import argparse

parser = argparse.ArgumentParser()

def initialize():
    parser.add_argument(
        "action",
        help="The action to perform (e.g. create, update)"
    )



def parse():
    args = parser.parse_args()

    if args.action == "create":
        cmd.create()
    elif args.action == "ls":
        cmd.ls()
    elif args.action == "delete":
        cmd.delete()

initialize()
parse()