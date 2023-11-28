import helper
import os

OUTPUT_DIR_NAME = "DnsLibs"

COPIED_FILES = [
    "Adguard.Dns.dll",
    "Adguard.Dns.pdb",
    "Adguard.Dns.xml"
]

COPIED_X86_FILES = [
    r"x86\AdguardDns.dll",
    r"x86\AdguardDns.pdb"
]

COPIED_X64_FILES = [  
    r"x64\AdguardDns.dll",
    r"x64\AdguardDns.pdb"
]

if __name__ == '__main__':
    try:
        print("Starting AdguardDns post build event script")
        args = helper.get_args()
        helper.copy_to_output(args, COPIED_FILES, OUTPUT_DIR_NAME)
        helper.copy_to_output(args, COPIED_X86_FILES, os.path.join(OUTPUT_DIR_NAME, 'x86'))
        helper.copy_to_output(args, COPIED_X64_FILES, os.path.join(OUTPUT_DIR_NAME, 'x64'))

        print("Adguard post build event script has been completed successfully")

    except Exception as ex:
        print(f"Adguard post build event script failed with an error {ex}")
        raise
