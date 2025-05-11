import argparse
import datetime
import logging
import os
import platform
import sys
import time
import yaml
import docker

from src.profile import Profile
from src import runner, containers, scanning, analysis


def banner():
    print(r"""
   ___          ___     _            _   _           
  / _ \_   _   /   \___| |_ ___  ___| |_(_)_   _____ 
 / /_)/ | | | / /\ / _ \ __/ _ \/ __| __| \ \ / / _ \
/ ___/| |_| |/ /_//  __/ ||  __/ (__| |_| |\ V /  __/
\/     \__, /___,' \___|\__\___|\___|\__|_| \_/ \___|
       |___/                                                                 
    """)


def is_system_platform_supported():
    machine_platform = platform.system().lower()
    if not machine_platform.startswith('linux'):
        print(f"\n[{time.strftime('%H:%M:%S')}] [CRITICAL] This system platform is not supported")
        logging.critical(f"Unsupported system platform")
        print("\nExiting ...\n")
        sys.exit(1)


def is_valid_file(filename, filetype):
    if not os.path.exists(filename):
        print(
            f"[{time.strftime('%H:%M:%S')}] [ERROR] Provided file '{filename}' does not exist")
        logging.error(f"Provided file '{filename}' does not exist")
        print("\nExiting program ...\n")
        sys.exit(1)
    else:
        if filetype == "yaml":
            if not filename.endswith(".yml") or filename.endswith(".yaml"):
                print(
                    f"[{time.strftime('%H:%M:%S')}] [ERROR] Provided file '{filename}' is not a yaml file")
                logging.error(f"Provided file '{filename}' is not a yaml file")
                print("\nExiting program ...\n")
                sys.exit(1)
    return True


def check_required_structure(profile):
    base_relative_path = os.path.dirname(os.path.realpath(sys.argv[0]))
    out_dir = os.path.join(base_relative_path, profile.output_folder_path)
    sandbox_dir = os.path.join(base_relative_path, profile.sandbox_folder_path)
    src_dir = os.path.join(base_relative_path, profile.src_folder_path)
    config_dir = os.path.join(base_relative_path, profile.config_folder_path)
    rules_dir = os.path.join(base_relative_path, profile.rules_folder_path)
    static_rules_dir = os.path.join(base_relative_path, profile.static_rules_folder_path)
    dynamic_rules_dir = os.path.join(base_relative_path, profile.dynamic_rules_folder_path)

    installation_script = os.path.join(base_relative_path, profile.installation_script)

    if not os.path.isdir(out_dir):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Creating '{out_dir}' for storing analysis output files ...")
        logging.info(f"Creating '{out_dir}' for storing analysis output files")
        os.mkdir(out_dir)

    missing_config_files = False
    missing_rules = False

    if not os.path.isdir(rules_dir):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Creating '{rules_dir}' for analysis rules ...")
        logging.info(f"Creating '{rules_dir}' for analysis rules")
        os.mkdir(rules_dir)
        missing_rules = True

    if not os.path.isdir(static_rules_dir):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Creating '{static_rules_dir}' for analysis rules ...")
        logging.info(f"Creating '{static_rules_dir}' for analysis rules")
        os.mkdir(static_rules_dir)
        missing_rules = True

    if not os.path.isdir(dynamic_rules_dir):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Creating '{dynamic_rules_dir}' for analysis rules ...")
        logging.info(f"Creating '{dynamic_rules_dir}' for analysis rules")
        os.mkdir(dynamic_rules_dir)
        missing_rules = True

    if not os.path.isdir(config_dir):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Creating '{config_dir}' for storing config files ...")
        logging.info(f"Creating '{config_dir}' for config files")
        os.mkdir(config_dir)
        missing_config_files = True

    if not os.path.isdir(sandbox_dir):
        print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Sandbox folder is missing, please reference 'https://github.com/MatejSkultety/PyDetective/tree/main/sandbox")
        logging.error("Sandbox folder is missing, please reference 'https://github.com/MatejSkultety/PyDetective/tree/main/sandbox")
        print("\nExiting program ...\n")
        sys.exit(1)

    if not os.path.isdir(src_dir):
        print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Src folder is missing, please reference 'https://github.com/MatejSkultety/PyDetective/tree/main/src ...")
        logging.error("Src folder is missing, please reference 'https://github.com/MatejSkultety/PyDetective/tree/main/src")
        print("\nExiting program ...\n")
        sys.exit(1)

    if not os.path.isfile(installation_script):
        print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Installation script is missing, please reference 'https://github.com/MatejSkultety/PyDetective'")
        logging.error("Installation script is missing, please reference 'https://github.com/MatejSkultety/PyDetective'")
        print("\nExiting program ...\n")
        sys.exit(1)

    if missing_rules:
        print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Rules for analysis are missing, create your own or reference 'https://github.com/MatejSkultety/PyDetective/tree/main/rules'")
        logging.error("Rules for analysis are missing, create your own or reference 'https://github.com/MatejSkultety/PyDetective/tree/main/rules'")
        print("\nExiting program ...\n")
        sys.exit(1)

    if missing_config_files:
        print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Create the missing config files or download them from 'https://github.com/MatejSkultety/PyDetective/tree/main/config'")
        logging.error("Create the missing config files or download them from 'https://github.com/MatejSkultety/PyDetective/tree/main/config'")
        print("\nExiting program ...\n")
        sys.exit(1)


def load_config(filename):
    try:
        with open(filename, "r") as ymlfile:
            config = yaml.safe_load(ymlfile)
            return config
    except yaml.parser.ParserError as e:
        print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Error occurred while parsing the configuration file")
        logging.error(f"Error occurred while parsing the configuration file ({e})")
        print("\nExiting program ...\n")
        sys.exit(1)


def arg_formatter():
    # source : https://stackoverflow.com/questions/52605094/python-argparse-increase-space-between-parameter-and-description
    def formatter(prog): return argparse.HelpFormatter(
        prog, max_help_position=52)

    return formatter


def parse_arguments():
    parser = argparse.ArgumentParser(formatter_class=arg_formatter(), prog='pydetective', description='Tool for detecting dangerous Python packages.')

    parser.add_argument(
        '-q', '--quiet', help="do not print banner", action='store_true')

    update_group = parser.add_argument_group('required options')
    required_args = update_group.add_mutually_exclusive_group(required=True)
    required_args.add_argument('-p', '--package', metavar='TEXT', 
                                help='package to analyze (e.g. "requests")')
  
    parser.add_argument('-c', '--config', metavar='FILE', default="config/config.yml",
                        help="configuration file (default: 'config/config.yml')")
    parser.add_argument('-w', '--write-extracted', action='store_true',
                        help='write extracted data to a JSON file')

    enable_group = parser.add_argument_group('enable options')
    enable_group.add_argument('-s', '--secure', action='store_true',
                            help="perform more secure analysis (don't execute suspicious files, disable network connection)")
    enable_group.add_argument('-i', '--install', action='store_true',
                            help="after analysis, (if safe) install the package on a host environment")
    enable_group.add_argument('-v', '--verbose', action='store_true',
                              help="print more detailed information")
    enable_group.add_argument('-t', '--test', action='store_true',
                              help="testing mode, execute analysis of sample package")

    return parser.parse_args(args=None if sys.argv[1:] else ['--help'])


def init_logger():
    logging_path = f"{os.path.dirname(os.path.realpath(sys.argv[0]))}/logs"
    if not os.path.isdir(logging_path):
        os.mkdir(logging_path)
    logging.basicConfig(format='%(created)f; %(asctime)s; %(levelname)s; %(name)s; %(message)s',
                        filename=f"{logging_path}/pydetective.log",
                        level=logging.DEBUG
                        )
    logger = logging.getLogger('__name__')


def main():
    os.system("clear")

    init_logger()
    is_system_platform_supported()

    analysis_timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    args = parse_arguments()

    if not args.quiet:
        banner()

    terminal_size = os.get_terminal_size()

    print('-' * terminal_size.columns)
    if is_valid_file(args.config, "yaml"):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Loading configuration file '{args.config}' ...")
        logging.info(f"Loading configuration file '{args.config}'")
        config = load_config(args.config)
        profile = Profile(config)

    print('-' * terminal_size.columns)
    print(f"[{time.strftime('%H:%M:%S')}] [INFO] Verifying required directory structure ...")
    logging.info("Verifying required directory structure")
    check_required_structure(profile)
    print('-' * terminal_size.columns)
    
    # Program logic goes here


    client = docker.from_env()
    containers.download_package("name", profile.output_folder_path, profile.downloaded_package_path)
    runner.analyze_package(client, profile, "sandbox/sample_malicious_package", secure_mode=False)
        



    print('-' * terminal_size.columns)
    print(f"\n[{time.strftime('%H:%M:%S')}] [INFO] All done. Exiting program ...\n")
    logging.info("All done. Exiting program")


if __name__ == '__main__':
    main()