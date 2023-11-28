import argparse
import sys
import os
import shutil

def print_usage():
    """ Prints the usage of script, which uses 'get_args()' method """
    print("you must specify SolutionDir, ProjectDir, TargetDir, ConfigurationName")
    print(f"python %script%.py --solution_dir=XXX --project_dir=XXX --target_dir=XXX --configuration_name=XXX")
    print(f"current args: {str(sys.argv)}")

def get_args():
    """ Parses, validates and returns arguments, passed to the script """
    parser = argparse.ArgumentParser()
    parser.add_argument('--solution_dir', dest='solution_dir', action='store')
    parser.add_argument('--project_dir', dest='project_dir', action='store')
    parser.add_argument('--target_dir', dest='target_dir', action='store')
    parser.add_argument('--configuration_name', dest='configuration_name', action='store')
    args = parser.parse_args()
    if not args.solution_dir or not args.project_dir or not args.target_dir or not args.configuration_name:
        print('One or more arguments are not specified')
        print_usage()
        print(f'Args are: {args}')
        raise ValueError("One or more arguments are not specified")

    print(f'Args are: {args}')
    return args

def copy_to_output(args, copied_files, output_dir_name):
    """ Copies files to the output directory"""
    print("Copying dnslibs files")
    output_dir = os.path.join(args.solution_dir, output_dir_name)
    if not os.path.exists(output_dir) or not os.path.isdir(output_dir):
        os.mkdir(output_dir)

    for copied_file in copied_files:
        pure_copied_file = os.path.basename(copied_file)
        shutil.copy(
            os.path.join(args.target_dir, copied_file),
            os.path.join(output_dir, pure_copied_file))
        print(f"File {copied_file} has been successfully copied to the {output_dir}")
