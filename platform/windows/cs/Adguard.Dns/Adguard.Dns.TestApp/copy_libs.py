import shutil
import os

##
# This is a helper script and used only by win-developers for making life more easy
##

DNS_LIB_DIR_NAME = "DnsLibs"
SOURCE = r"D:\Work\Repo\dns-libs\platform\windows\cs\Adguard.Dns"
SAMPLE_APP_DEST = r"D:\Work\Repo\dns-libs\platform\windows\cs\Adguard.Dns\Adguard.Dns.TestApp"

if __name__ == '__main__':
    try:
        print "Start copying from corelibs files %s to %s " %(SOURCE, SAMPLE_APP_DEST)
        source_path = os.path.join(SOURCE, DNS_LIB_DIR_NAME)
        sample_app_dest_path = os.path.join(SAMPLE_APP_DEST, DNS_LIB_DIR_NAME)

        if not os.path.exists(sample_app_dest_path):
            os.mkdir(sample_app_dest_path)

        for file in os.listdir(source_path):
            shutil.copy(
                os.path.join(source_path, file),
                os.path.join(sample_app_dest_path, file))
            print "File %s has been successfully copied to the %s" %(file, sample_app_dest_path)

        raw_input('Press enter to continue: ')
    except Exception as ex:
        print "Copying files failed with an error %s" %ex
        raw_input('Press enter to continue: ')