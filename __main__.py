import os
import argparse
import sys

import __main__old

def arg_formatter():
    def formatter(prog): return argparse.HelpFormatter(
        prog, max_help_position=52)
    return formatter


def parse_args():
    parser = argparse.ArgumentParser(
        formatter_class=arg_formatter(), prog='pydetective', description="Scan Python packages for malware.")

    parser.add_argument('-t', '--test', action='store_true',
                        help='test the script')

    return parser.parse_args(args=None if sys.argv[1:] else ['--help'])


def main():
    args = parse_args()

    terminal_size = os.get_terminal_size()
    print('-' * terminal_size.columns)

    if args.test:
        __main__old.main()
        print('-' * terminal_size.columns)


if __name__ == '__main__':
    main()
