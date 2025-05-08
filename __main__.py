import os
import argparse
import sys

from src.utils import runner
from src.analysis import static

def arg_formatter():
    def formatter(prog): return argparse.HelpFormatter(
        prog, max_help_position=52)
    return formatter


def parse_args():
    parser = argparse.ArgumentParser(
        formatter_class=arg_formatter(), prog='pydetective', description="Scan Python packages for malware.")

    parser.add_argument('-t', '--test', action='store_true',
                        help='test the script')
    
    parser.add_argument('-l', '--local', action='store_true',
                        help='install local package')
    
    parser.add_argument('-d', '--dev', action='store_true',
                        help='for development purposes only')

    return parser.parse_args(args=None if sys.argv[1:] else ['--help'])


def main():
    args = parse_args()

    terminal_size = os.get_terminal_size()
    print('-' * terminal_size.columns)

    if args.test:
        runner.install_in_sandbox("purposefully-malicious")
        print('-' * terminal_size.columns)

    if args.local:
        runner.install_in_sandbox("/app/sample_package_skuty")
        print('-' * terminal_size.columns)

    if args.dev:
        static.scan_file_with_rules(None, "src/analysis/yara_rules/malware")
        print('-' * terminal_size.columns)


if __name__ == '__main__':
    main()
