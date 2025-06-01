import argparse
import datetime
import logging
import os
import platform
import sys
import time

import docker
import mysql.connector
import yaml

from src import analysis, containers, evaluation, runner
from src.profile import Profile


def banner() -> None:
    """
    Prints the banner of the application created with ASCII art.

    Args:
        None
    Returns:
        None
    """
    print(r"""
   ___          ___     _            _   _           
  / _ \_   _   /   \___| |_ ___  ___| |_(_)_   _____ 
 / /_)/ | | | / /\ / _ \ __/ _ \/ __| __| \ \ / / _ \
/ ___/| |_| |/ /_//  __/ ||  __/ (__| |_| |\ V /  __/
\/     \__, /___,' \___|\__\___|\___|\__|_| \_/ \___|
       |___/                                                                 
    """)


def is_system_platform_supported() -> bool:
    """
    Checks if the system platform is supported (Linux).
    Exits the program if the platform is not supported.

    Args:
        None
    Returns:
        bool: True if the platform is supported, otherwise exits the program.
    """
    machine_platform = platform.system().lower()
    if not machine_platform.startswith('linux'):
        print(f"[{time.strftime('%H:%M:%S')}] [CRITICAL] This system platform is not supported")
        logging.critical(f"Unsupported system platform")
        print("Exiting ...")
        sys.exit(1)
    return True


def is_root() -> bool:
    """
    Checks if the script is running as root (UID 0).
    Exits the program if not running as root.

    Args:
        None
    Returns:
        bool: True if running as root, otherwise exits the program.
    """
    if os.geteuid() != 0:
        print(f"[{time.strftime('%H:%M:%S')}] [CRITICAL] This application must be run as root (sudo privileges required).")
        logging.critical("Application not run as root (sudo required).")
        print("Exiting ...")
        sys.exit(1)
    return True


def is_yaml_file(filename: str) -> bool:
    """
    Checks if the provided file exists and is of the correct type (yaml).
    Exits the program if the file does not exist or is not of the correct type.

    Args:
        filename (str): The path to the file to check.
    Returns:
        bool: True if the file exists and is of the correct type, otherwise exits the program.
    """
    if not os.path.exists(filename):
        print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Provided file '{filename}' does not exist")
        logging.error(f"Provided file '{filename}' does not exist")
        print("Exiting program ...")
        sys.exit(1)
    if not (filename.endswith(".yml") or filename.endswith(".yaml")):
        print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Provided file '{filename}' is not a yaml file")
        logging.error(f"Provided file '{filename}' is not a yaml file")
        print("Exiting program ...")
        sys.exit(1)
    return True


def is_local_package(package_name: str) -> bool:
    """
    Checks if the provided package name is a local package (directory or archive).

    Args:
        package_name (str): The name of the package to check.
    Returns:
        bool: True if the package is a local package (directory or archive), otherwise False.
    """
    if '/' in package_name or '\\' in package_name:
        if os.path.exists(package_name):
            if os.path.isdir(package_name): # Directory check
                logging.info(f"Local package '{package_name}' found")
                return True
            elif package_name.endswith('.tar.gz') or package_name.endswith('.whl'): # Archive check
                logging.info(f"Local package archive '{package_name}' found")
                return True
            else:
                print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Provided path '{package_name}' is not a directory or a recognized archive")
                logging.error(f"Provided path '{package_name}' is not a directory or a recognized archive")
                print("Exiting program ...")
                sys.exit(1)
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Provided package path '{package_name}' does not exist")
            logging.error(f"Provided package path '{package_name}' does not exist")
            print("Exiting program ...")
            sys.exit(1)
    else:
        return False


def check_required_structure(profile: Profile) -> None:
    """
    Checks if the required directory structure for PyDetective exists.
    If any directories are missing, they are created.
    Exits the program if critical directories are missing.

    Args:
        profile (Profile): The profile object containing paths and configuration.
    Returns:
        None
    """
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
        print("Exiting program ...")
        sys.exit(1)
    if not os.path.isdir(src_dir):
        print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Src folder is missing, please reference 'https://github.com/MatejSkultety/PyDetective/tree/main/src ...")
        logging.error("Src folder is missing, please reference 'https://github.com/MatejSkultety/PyDetective/tree/main/src")
        print("Exiting program ...")
        sys.exit(1)
    if not os.path.isfile(installation_script):
        print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Installation script is missing, please reference 'https://github.com/MatejSkultety/PyDetective'")
        logging.error("Installation script is missing, please reference 'https://github.com/MatejSkultety/PyDetective'")
        print("Exiting program ...")
        sys.exit(1)
    if missing_rules:
        print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Rules for analysis are missing, create your own or reference 'https://github.com/MatejSkultety/PyDetective/tree/main/rules'")
        logging.error("Rules for analysis are missing, create your own or reference 'https://github.com/MatejSkultety/PyDetective/tree/main/rules'")
        print("Exiting program ...")
        sys.exit(1)
    if missing_config_files:
        print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Create the missing config files or download them from 'https://github.com/MatejSkultety/PyDetective/tree/main/config'")
        logging.error("Create the missing config files or download them from 'https://github.com/MatejSkultety/PyDetective/tree/main/config'")
        print("Exiting program ...")
        sys.exit(1)


def load_config(filename: str) -> dict:
    """
    Loads the configuration from a YAML file.

    Args:
        filename (str): The path to the YAML configuration file.
    Returns:
        dict: The loaded configuration as a dictionary.
    """
    try:
        with open(filename, "r") as ymlfile:
            config = yaml.safe_load(ymlfile)
            return config
    except yaml.parser.ParserError as e:
        print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Error occurred while parsing the configuration file")
        logging.error(f"Error occurred while parsing the configuration file ({e})")
        print("Exiting program ...")
        sys.exit(1)


def arg_formatter(): # TODO
    # source : https://stackoverflow.com/questions/52605094/python-argparse-increase-space-between-parameter-and-description
    def formatter(prog): return argparse.HelpFormatter(
        prog, max_help_position=52)

    return formatter


def parse_arguments() -> argparse.Namespace:
    """
    Parses command line arguments for the PyDetective application.

    Args:
        None
    Returns:
        argparse.Namespace: The parsed command line arguments.
    """
    parser = argparse.ArgumentParser(
        formatter_class=arg_formatter(), prog='pydetective',
        description='Tool for detecting dangerous Python packages.'
    )

    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        'package_name', nargs='?', metavar='PACKAGE',
        help='Name of the package to analyze (e.g. "requests") or path to local package (e.g. "path/to/package") or .txt file with list of packages (e.g. "path/to/requirements.txt")'
    )
    mode_group.add_argument(
        '-t', '--test', action='store_true',
        help="Testing mode, execute analysis of sample package"
    )
    mode_group.add_argument(
        '-db', '--database', metavar='PACKAGE',
        help="Display history of analyzed package from MySQL database or entire database if 'ALL' is specified"
    )
    parser.add_argument(
        '-i', '--install', action='store_true',
        help="After analysis, (if safe) install the package on a host environment"
    )
    parser.add_argument(
        '-k', '--keep_files', action='store_true',
        help="Don't delete downloaded package files after analysis (sandbox/downloaded_package)"
    )
    parser.add_argument(
        '-c', '--config', metavar='FILE', default='config/pydetective.yaml',
        help="Configuration file (default: 'config/pydetective.yaml')"
    )

    details_level_group = parser.add_mutually_exclusive_group()
    details_level_group.add_argument(
        '-q', '--quiet', action='store_true',
        help='Do not print banner'
    )
    details_level_group.add_argument(
        '-v', '--verbose', action='store_true',
        help='Enable more detailed output'
    )

    analysis_group = parser.add_argument_group('analysis parameters')
    analysis_group.add_argument(
        '-s', '--secure', action='store_true',
        help="Perform more secure analysis (don't execute suspicious files, disable network connection)"
    )
    analysis_group.add_argument(
        '-d', '--deep', action='store_true',
        help="Scan entire sandbox OS after package installation"
    )

    output_group = parser.add_argument_group('output options')
    output_group.add_argument(
        '-w', '--write', metavar='FILE', default='out/pydetective_result.json',
        help='Write extracted data to a JSON file'
    )
    return parser.parse_args(args=None if sys.argv[1:] else ['--help'])


def parse_requirements_file(package_arg: str) -> list[str]:
    """
    Parses a requirements.txt file and returns a list of package names.
    If the argument is not a file, it returns a list with the single package name.

    Args:
        package_arg (str): The package name or path to the requirements file.
    Returns:
        list[str]: A list of package names to analyze.
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


def init_logger() -> None:
    """
    Initializes the logger for the application.
    Creates a logs directory if it does not exist and sets up the logging configuration.

    Args:
        None
    Returns:
        None
    """
    logging_path = f"{os.path.dirname(os.path.realpath(sys.argv[0]))}/logs"
    if not os.path.isdir(logging_path):
        os.mkdir(logging_path)
    logging_format = '%(created)f; %(asctime)s; %(levelname)s; %(name)s; %(message)s'
    logging.basicConfig(format=logging_format, filename=f"{logging_path}/pydetective.log", level=logging.DEBUG)
    logger = logging.getLogger('__name__')


def init_database(profile: Profile) -> mysql.connector.connection.MySQLConnection:
    """
    Initializes the MySQL database connection and creates the required table if it does not exist.

    Args:
        profile (Profile): The profile object containing database configuration.
    Returns:
        mysql.connector.connection.MySQLConnection: The initialized database connection.
    """
    try:
        connection = mysql.connector.connect(host=profile.db_host, user=profile.db_user, password=profile.db_password, database=profile.db_name)
        cursor = connection.cursor()
        cursor.execute(f"""
            CREATE TABLE IF NOT EXISTS {profile.db_table} (
                id INT AUTO_INCREMENT PRIMARY KEY,
                package_name VARCHAR(255),
                version VARCHAR(64),
                verdict VARCHAR(16),
                timestamp VARCHAR(32),
                hash VARCHAR(64) UNIQUE,
                evaluation_result JSON
            )
        """)
        connection.commit()
    except Exception as e:
        logging.error(f"Failed to initialize MySQL database: {e}")
        print(f"[{time.strftime('%H:%M:%S')}] [WARNING] Failed to initialize MySQL database: {e}")
        return None
    else:
        return connection


def init_pydetective(args: argparse.Namespace) -> Profile:
    """
    Initializes the PyDetective application by setting up the logger, checking system requirements,
    loading the configuration file, and verifying the required directory structure. Profile attributes
    are set based on the configuration and command line arguments.

    Args:
        args (argparse.Namespace): The parsed command line arguments.
    Returns:
        Profile: The initialized profile object containing configuration and paths.
    """
    init_logger()
    logging.info("Initializing PyDetective")
    is_system_platform_supported()
    is_root()

    if is_yaml_file(args.config):
        logging.info(f"Loading configuration file '{args.config}'")
        if not args.quiet:
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] Loading configuration file '{args.config}'...")
        config = load_config(args.config)
        profile = Profile(config, args)
        #Set profile attributes which are not in config file
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
    # Clean output folder
    for filename in os.listdir(profile.output_folder_path):
        file_path = os.path.join(profile.output_folder_path, filename)
        try:
            if os.path.isfile(file_path):
                os.remove(file_path)
        except Exception as e:
            print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Failed to delete {file_path}: {e}")
            logging.error(f"Failed to delete {file_path}: {e}")
    if args.write:
        if os.path.exists(args.write):
            try:
                os.remove(args.write)
            except Exception as e:
                logging.error(f"Failed to delete output file '{args.write}': {e}")

    profile.docker_client = docker.from_env()
    profile.database_connection = init_database(profile)
    if profile.args.database is None:
        logging.info("Compiling detection rules")
        if not args.quiet:
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] Compiling detection rules...")
        profile.yara_rules = analysis.compile_yara_rules(profile.static_rules_folder_path)
        logging.info("Starting analysis")
        if not args.quiet:
            print(f"[{time.strftime('%H:%M:%S')}] [INFO] Everything is ready, starting analysis...")
            print('.' * profile.terminal_size.columns)
    return profile


def main() -> None:
    """
    Main function to run the PyDetective application.
    It initializes the application, parses command line arguments, checks for local packages,
    downloads packages, analyzes them, and handles the results based on the command line options.

    Args:
        None
    Returns:
        None
    """
    os.system("clear")
    args = parse_arguments()
    if not args.quiet:
        banner()
    profile = init_pydetective(args)

    if args.database is not None:
        logging.debug(f"Database mode activated for package '{args.database}'")
        try:
            evaluation.read_db_results(profile)
        except Exception as e:
            print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Database connection failed: {e}")
            logging.error(f"Database connection failed: {e}")
        print('.' * profile.terminal_size.columns)
        print(f"[{time.strftime('%H:%M:%S')}] [INFO] All done. Exiting program ...")
        logging.info("All done. Exiting program")
        sys.exit(0)


    packages_to_analyze = parse_requirements_file(profile.package_name)
    for package_to_analyze in packages_to_analyze:
        profile.package_name = package_to_analyze



        profile.local_package = is_local_package(profile.package_name)
        try:
            package_path = containers.download_package(profile)
        except Exception as e:
            print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Failed to download package '{profile.package_name}': {e}")
            logging.error(f"Failed to download package '{profile.package_name}': {e}")
            print("Exiting program ...")
            sys.exit(1)

        verdict = runner.analyze_package(profile)

        if args.install and verdict == evaluation.Verdict.SAFE.value:
            runner.install_package_on_host(package_path, profile.local_package)

        if not args.keep_files:
            containers.delete_package(profile.downloaded_package_path)





    print('.' * profile.terminal_size.columns)
    print(f"[{time.strftime('%H:%M:%S')}] [INFO] All done. Exiting program ...")
    logging.info("All done. Exiting program")


if __name__ == '__main__':
    main()
