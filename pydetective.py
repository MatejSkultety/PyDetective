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


def is_root():
    """
    Checks if the script is running as root (UID 0).
    Exits the program if not running as root.
    """
    if os.geteuid() != 0:
        print(f"\n[{time.strftime('%H:%M:%S')}] [CRITICAL] This application must be run as root (sudo privileges required).")
        logging.critical("Application not run as root (sudo required).")
        print("\nExiting ...\n")
        sys.exit(1)


def is_valid_file(filename, filetype):
    if not os.path.exists(filename):
        print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Provided file '{filename}' does not exist")
        logging.error(f"Provided file '{filename}' does not exist")
        print("\nExiting program ...\n")
        sys.exit(1)
    else:
        if filetype == "yaml":
            if not (filename.endswith(".yml") or filename.endswith(".yaml")):
                print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Provided file '{filename}' is not a yaml file")
                logging.error(f"Provided file '{filename}' is not a yaml file")
                print("\nExiting program ...\n")
                sys.exit(1)
    return True


def is_local_package(package_name):
    if '/' in package_name or '\\' in package_name:
        if os.path.exists(package_name):
            if os.path.isdir(package_name):
                logging.info(f"Local package '{package_name}' found")
                return True
            else:
                print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Provided path '{package_name}' is not a directory")
                logging.error(f"Provided path '{package_name}' is not a directory")
                print("\nExiting program ...\n")
                sys.exit(1)
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Provided package path '{package_name}' does not exist")
            logging.error(f"Provided package path '{package_name}' does not exist")
            print("\nExiting program ...\n")
            sys.exit(1)
    else:
        return False


def check_required_structure(profile):
    base_relative_path = os.path.dirname(os.path.realpath(sys.argv[0]))
    out_dir = os.path.join(base_relative_path, profile.output_folder_path)
    sandbox_dir = os.path.join(base_relative_path, profile.sandbox_folder_path)
    downloaded_package_dir = os.path.join(base_relative_path, profile.downloaded_package_path)
    src_dir = os.path.join(base_relative_path, profile.src_folder_path)
    config_dir = os.path.join(base_relative_path, profile.config_folder_path)
    rules_dir = os.path.join(base_relative_path, profile.rules_folder_path)
    static_rules_dir = os.path.join(base_relative_path, profile.static_rules_folder_path)
    dynamic_rules_dir = os.path.join(base_relative_path, profile.dynamic_rules_folder_path)

    installation_script = os.path.join(base_relative_path, profile.installation_script)

    if not os.path.isdir(downloaded_package_dir):
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Creating '{downloaded_package_dir}' for temporary storage of package files ...")
        logging.info(f"Creating '{downloaded_package_dir}' for temporary storage of package files")
        os.mkdir(downloaded_package_dir)

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
    exclusive_group = parser.add_mutually_exclusive_group(required=True)
    exclusive_group.add_argument('package_name', nargs='?', metavar='PACKAGE', help='Name of the package to analyze (e.g. "requests") or path to local package (e.g. "path/to/package") or .txt file with list of packages (e.g. "path/to/requirements.txt")')
    exclusive_group.add_argument('-t', '--test', action='store_true', help="Testing mode, execute analysis of sample package")
    parser.add_argument('-i', '--install', action='store_true', help="After analysis, (if safe) install the package on a host environment")
    parser.add_argument('-k', '--keep-files', action='store_true', help="Don't delete downloaded package files after analysis (sandbox/downloaded_package)")
    parser.add_argument('-c', '--config', metavar='FILE', default='config/pydetective.yaml', help="Configuration file (default: 'config/pydetective.yaml')")
    details_level_group = parser.add_mutually_exclusive_group()
    details_level_group.add_argument('-q', '--quiet', action='store_true', help='Do not print banner')
    details_level_group.add_argument('-v', '--verbose', action='store_true', help='Enable more detailed output')
    analysis_group = parser.add_argument_group('analysis parameters')
    analysis_group.add_argument('-s', '--secure', action='store_true', help="Perform more secure analysis (don't execute suspicious files, disable network connection)")
    analysis_group.add_argument('-d', '--deep', action='store_true', help="Scan entire sandbox OS after package installation")
    output_group = parser.add_argument_group('output options')
    output_group.add_argument('-w', '--write', metavar='FILE', default='out/pydetective_result.json', help='Write extracted data to a JSON file')
    return parser.parse_args(args=None if sys.argv[1:] else ['--help'])


def parse_requirements_file(package_arg: str) -> list[str]:
    """
    Parses a requirements.txt file and returns a list of package names.
    """
    packages = []
    if package_arg.endswith('.txt'):
        try:
            with open(package_arg, 'r') as file:
                for line in file:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        packages.append(line)
        except FileNotFoundError:
            print(f"[{time.strftime('%H:%M:%S')}] [ERROR] The specified requirements file '{package_arg}' does not exist.")
            logging.error(f"The specified requirements file '{package_arg}' does not exist.")
            sys.exit(1)
        except Exception as e:
            print(f"[{time.strftime('%H:%M:%S')}] [ERROR] An error occurred while reading the requirements file: {e}")
            logging.error(f"An error occurred while reading the requirements file: {e}")
            sys.exit(1)
    else:
        packages.append(package_arg)
    return packages


def init_logger():
    logging_path = f"{os.path.dirname(os.path.realpath(sys.argv[0]))}/logs"
    if not os.path.isdir(logging_path):
        os.mkdir(logging_path)
    logging.basicConfig(format='%(created)f; %(asctime)s; %(levelname)s; %(name)s; %(message)s',
                        filename=f"{logging_path}/pydetective.log",
                        level=logging.DEBUG
                        )
    logger = logging.getLogger('__name__')


def init_pydetective(args: argparse.Namespace) -> Profile:

    init_logger()
    logging.info("Initializing PyDetective")
    is_system_platform_supported()
    is_root()

    if is_valid_file(args.config, "yaml"):
        logging.info(f"Loading configuration file '{args.config}'")
        if not args.quiet:
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] Loading configuration file '{args.config}'...")
        config = load_config(args.config)
        profile = Profile(config, args)

        profile.analysis_timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        profile.terminal_size = os.get_terminal_size()
        if args.test:
            profile.package_name = profile.sample_package_path
            profile.args.install = False
        else:
            profile.package_name = args.package_name

    logging.info("Verifying required directory structure")
    if not args.quiet:
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Verifying required directory structure...")
    check_required_structure(profile)

    profile.docker_client = docker.from_env()
    logging.info("Compiling detection rules")
    if not args.quiet:
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Compiling detection rules...")
    profile.static_analyzer = analysis.StaticAnalyzer(profile.static_rules_folder_path)
    logging.info("Starting analysis")
    if not args.quiet:
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] Everything is ready, starting analysis...")
    print('-' * profile.terminal_size.columns)

    return profile


def main():

    os.system("clear")
    args = parse_arguments()
    if not args.quiet:
        banner()
    profile = init_pydetective(args)

    packages_to_analyze = parse_requirements_file(profile.package_name)
    for package_to_analyze in packages_to_analyze:
        profile.package_name = package_to_analyze



        local_package = is_local_package(profile.package_name)
        try:
            package_path = containers.download_package(profile, local_package)
        except Exception as e:
            print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Failed to download package '{profile.package_name}': {e}")
            logging.error(f"Failed to download package '{profile.package_name}': {e}")
            print("\nExiting program ...\n")
            sys.exit(1)

        verdict = runner.analyze_package(profile, secure_mode=False)
        # TODO add evaluation of the results


        if args.install and True:
            runner.install_package_on_host(package_path, local_package)

        if not args.keep_files:
            containers.delete_package(profile.downloaded_package_path)





    print('-' * profile.terminal_size.columns)
    print(f"\n[{time.strftime('%H:%M:%S')}] [INFO] All done. Exiting program ...\n")
    logging.info("All done. Exiting program")


if __name__ == '__main__':
    main()