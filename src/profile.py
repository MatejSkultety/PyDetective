import logging
import sys
import time


class Profile:




    def __init__(self, config, args):

        self.args = args
        self.docker_client = None
        self.yara_rules = None
        self.package_name = None
        self.database_connection = None
        self.local_package = False

        self.enrichment_services = config.get('enrichment_services')
        if self.enrichment_services:
            self.otx_api_key = self.enrichment_services.get('otx_api_key')
            self.otx_ipv4_indicators_url = self.enrichment_services.get('otx_ipv4_indicators_url')
            self.otx_domain_indicators_url = self.enrichment_services.get('otx_domain_indicators_url')
            
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Container configurations are not present in the configuration file ...")
            logging.error(f"Container configurations are not present in the configuration file")
            print("Exiting program ...")
            sys.exit(1)


        self.file_paths = config.get('file_paths')
        if self.file_paths:
            # Load all file paths from the configuration
            self.installation_script = self.file_paths.get('installation_script')
            self.rules_folder_path = self.file_paths.get('rules_folder_path')
            self.static_rules_folder_path = self.file_paths.get('static_rules_folder_path')
            self.dynamic_rules_folder_path = self.file_paths.get('dynamic_rules_folder_path')
            self.logging_path = self.file_paths.get('logging_path')
            self.output_folder_path = self.file_paths.get('output_folder_path')
            self.static_result_path = self.file_paths.get('static_result_path')
            self.syscalls_result_path = self.file_paths.get('syscalls_result_path')
            self.network_result_path = self.file_paths.get('network_result_path')
            self.post_install_result_path = self.file_paths.get('post_install_result_path')
            self.network_output_path = self.file_paths.get('network_output_path')
            self.syscalls_output_path = self.file_paths.get('syscalls_output_path')
            self.evaluation_output_path = self.file_paths.get('evaluation_output_path')
            self.sandbox_folder_path = self.file_paths.get('sandbox_folder_path')
            self.sample_package_path = self.file_paths.get('sample_package_path')
            self.downloaded_package_path = self.file_paths.get('downloaded_package_path')
            self.archives_path = self.file_paths.get('archives_path')
            self.extracted_path = self.file_paths.get('extracted_path')
            self.falco_config_path = self.file_paths.get('falco_config_path')
            self.container_dir_path = self.file_paths.get('container_dir_path')
            self.pypi_projects_dependency_path = self.file_paths.get('pypi_projects_dependency_path')
            self.config_folder_path = self.file_paths.get('config_folder_path')
            self.src_folder_path = self.file_paths.get('src_folder_path')
            self.deepscan_output_path = self.file_paths.get('deepscan_output_path')
            self.database_folder_path = self.file_paths.get('database_folder_path')
            self.database_path = self.file_paths.get('database_path')
            self.tcpdump_path = self.file_paths.get('tcpdump_path')

            # Check if any required file path is missing
            if any(file_path is None for file_path in self.file_paths.values()):
                print(f"[{time.strftime('%H:%M:%S')}] [ERROR] The configuration file does not contain all required file paths ...")
                logging.error(f"The configuration file does not contain all required file paths")
                print("Exiting program ...")
                sys.exit(1)
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [ERROR] File paths are not present in the configuration file ...")
            logging.error(f"File paths are not present in the configuration file")
            print("Exiting program ...")
            sys.exit(1)

        self.default_names = config.get('default_names')
        if self.default_names:
            self.image_name = self.default_names.get('image_name')
            self.image_tag = self.default_names.get('image_tag')
            self.db_table = self.default_names.get('db_table_name')
            self.tcpdump_image_tag = self.default_names.get('tcpdump_image_tag')

            # Check if any required container configuration is missing
            if any(container_value is None for container_value in self.default_names.values()):
                print(f"[{time.strftime('%H:%M:%S')}] [ERROR] The configuration file does not contain all required container configurations ...")
                logging.error(f"The configuration file does not contain all required container configurations")
                print("Exiting program ...")
                sys.exit(1)
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Container configurations are not present in the configuration file ...")
            logging.error(f"Container configurations are not present in the configuration file")
            print("Exiting program ...")
            sys.exit(1)

        self.ignored_ips = config.get('ignored_ips')
        if self.ignored_ips is not None:
            if not isinstance(self.ignored_ips, list) or not all(isinstance(ip, str) for ip in self.ignored_ips):
                print(f"[{time.strftime('%H:%M:%S')}] [ERROR] 'ignored_ips' must be a list of strings in the configuration file ...")
                logging.error(f"'ignored_ips' must be a list of strings in the configuration file")
                print("Exiting program ...")
                sys.exit(1)
        else:
            self.ignored_ips = []

        self.ignored_domains = config.get('ignored_domains')
        if self.ignored_domains is not None:
            if not isinstance(self.ignored_domains, list) or not all(isinstance(domain, str) for domain in self.ignored_domains):
                print(f"[{time.strftime('%H:%M:%S')}] [ERROR] 'ignored_domains' must be a list of strings in the configuration file ...")
                logging.error(f"'ignored_domains' must be a list of strings in the configuration file")
                print("Exiting program ...")
                sys.exit(1)
        else:
            self.ignored_domains = []

        self.ignored_syscalls = config.get('ignored_syscalls')
        if self.ignored_syscalls is not None:
            if not isinstance(self.ignored_syscalls, list) or not all(isinstance(syscall, str) for syscall in self.ignored_syscalls):
                print(f"[{time.strftime('%H:%M:%S')}] [ERROR] 'ignored_syscalls' must be a list of strings in the configuration file ...")
                logging.error(f"'ignored_syscalls' must be a list of strings in the configuration file")
                print("Exiting program ...")
                sys.exit(1)
        else:
            self.ignored_syscalls = []

        self.thresholds = config.get('thresholds')
        if self.thresholds:
            self.MAX_TOLERATED_LOW_PRIORITY_NETWORK = self.thresholds.get('MAX_TOLERATED_LOW_PRIORITY_NETWORK', 0)
            self.MAX_TOLERATED_HIGH_PRIORITY_NETWORK = self.thresholds.get('MAX_TOLERATED_HIGH_PRIORITY_NETWORK', 0)
            self.MAX_TOLERATED_LOW_PRIORITY_SYSCALLS = self.thresholds.get('MAX_TOLERATED_LOW_PRIORITY_SYSCALLS', 0)
            self.MAX_TOLERATED_HIGH_PRIORITY_SYSCALLS = self.thresholds.get('MAX_TOLERATED_HIGH_PRIORITY_SYSCALLS', 0)
            self.MAX_TOLERATED_LOW_PRIORITY_STATIC = self.thresholds.get('MAX_TOLERATED_LOW_PRIORITY_STATIC', 0)
            self.MAX_TOLERATED_HIGH_PRIORITY_STATIC = self.thresholds.get('MAX_TOLERATED_HIGH_PRIORITY_STATIC', 0)
            self.MAX_TOLERATED_HIGH_PRIORITY_POST_INSTALL = self.thresholds.get('MAX_TOLERATED_HIGH_PRIORITY_POST_INSTALL', 0)
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Thresholds are not present in the configuration file ...")
            logging.error(f"Thresholds are not present in the configuration file")
            print("Exiting program ...")
            sys.exit(1)

        self.terminal_size = None
        self.analysis_timestamp = None
