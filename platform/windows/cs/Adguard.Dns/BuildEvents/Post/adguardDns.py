import helper

OUTPUT_DIR_NAME = "DnsLibs"

COPIED_FILES = [
    "Adguard.Dns.dll",
    "Adguard.Dns.pdb",
    "Adguard.Dns.xml",
    "AdguardDns.dll",
    "AdguardDns.pdb"
]

if __name__ == '__main__':
    try:
        print("Starting AdguardDns post build event script")
        args = helper.get_args()
        helper.copy_to_output(args, COPIED_FILES, OUTPUT_DIR_NAME)

        print("Adguard post build event script has been completed successfully")

    except Exception as ex:
        print(f"Adguard post build event script failed with an error {ex}")
        raise
