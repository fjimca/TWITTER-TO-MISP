# -*- coding: utf-8 -*-

import argparse
import sys
from main import run


def parse_args(args):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-L", "--list", nargs="+", required=False, metavar='account', help="List of users to follow separated by space"
    )
    parser.add_argument(
        "-F", "--file", nargs=1, required=False, type=str, help="File with list of users to follow. One in each line"
    )
    parser.add_argument(
        "-T", "--tweet", nargs=1, required=False, help="Tweet id to show"
    )
    parser.add_argument("-v", "--verbose", dest="verbose",  help="Show debug information", action="store_true")

    return parser.parse_args(args)


if __name__ == "__main__":
    
    if len(sys.argv) < 2:
       # Es obligatorio introducir un parámetro
       print ('\n\n##### You must enter at least one parameter. Try -h ###\n')
       sys.exit()
    args = parse_args(sys.argv[1:])
    run(**vars(args))
