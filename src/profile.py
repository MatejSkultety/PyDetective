import logging
import time
import sys


class Profile:




    def __init__(self, config, args):

        self.args = args
        self.docker_client = None
        self.static_analyzer = None
        self.package_name = None

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
            self.archives_local_path = self.file_paths.get('archives_local_path')
            self.extracted_path = self.file_paths.get('extracted_path')
            self.extracted_local_path = self.file_paths.get('extracted_local_path')
            self.falco_config_path = self.file_paths.get('falco_config_path')
            self.container_dir_path = self.file_paths.get('container_dir_path')
            self.pypi_projects_dependency_path = self.file_paths.get('pypi_projects_dependency_path')
            self.config_folder_path = self.file_paths.get('config_folder_path')
            self.src_folder_path = self.file_paths.get('src_folder_path')

            # Check if any required file path is missing
            if any(file_path is None for file_path in self.file_paths.values()):
                print(f"[{time.strftime('%H:%M:%S')}] [ERROR] The configuration file does not contain all required file paths ...")
                logging.error(f"The configuration file does not contain all required file paths")
                print("\nExiting program ...\n")
                sys.exit(1)
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [ERROR] File paths are not present in the configuration file ...")
            logging.error(f"File paths are not present in the configuration file")
            print("\nExiting program ...\n")
            sys.exit(1)

        self.containers = config.get('containers')
        if self.containers:
            self.image_name = self.containers.get('image_name')
            self.image_tag = self.containers.get('image_tag')

            # Check if any required container configuration is missing
            if any(container_value is None for container_value in self.containers.values()):
                print(f"[{time.strftime('%H:%M:%S')}] [ERROR] The configuration file does not contain all required container configurations ...")
                logging.error(f"The configuration file does not contain all required container configurations")
                print("\nExiting program ...\n")
                sys.exit(1)
        else:
            print(f"[{time.strftime('%H:%M:%S')}] [ERROR] Container configurations are not present in the configuration file ...")
            logging.error(f"Container configurations are not present in the configuration file")
            print("\nExiting program ...\n")
            sys.exit(1)



        self.terminal_size = None
        self.analysis_timestamp = None

        