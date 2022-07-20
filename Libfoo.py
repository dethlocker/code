# 1. Run find commands to check for ARC
# 2. Run find command to check for stack canary
# 3. Run find command to check for PIC
# 4. Print all the failed libraries in the search
# 5. Print all stack smashing libraries
# Felix Alcala dethlocker@0xdeadbeef.ai
# "I am a 10, but on the pH scale; I'm just basic. A simple human. Being."
import os
import sys
import subprocess
import re

def find_arc(path):
    """
    Finds all the libraries that are compiled with ARC
    """
    arc_libs = []
    for root, dirs, files in os.walk(path):
        for file in files:
            if file.endswith(".a"):
                file_path = os.path.join(root, file)
                cmd = "otool -oV " + file_path + " | grep -i __objc_release"
                output = subprocess.check_output(cmd, shell=True)
                if output:
                    arc_libs.append(file_path)
    return arc_libs

def find_stack_canary(path):
    """
    Finds all the libraries that are compiled with stack canary
    """
    stack_canary_libs = []
    for root, dirs, files in os.walk(path):
        for file in files:
            if file.endswith(".a"):
                file_path = os.path.join(root, file)
                cmd = "otool -oV " + file_path + " | grep -i __stack_chk_fail"
                output = subprocess.check_output(cmd, shell=True)
                if output:
                    stack_canary_libs.append(file_path)
    return stack_canary_libs

def find_pic(path):
    """
    Finds all the libraries that are compiled with PIC
    """
    pic_libs = []
    for root, dirs, files in os.walk(path):
        for file in files:
            if file.endswith(".a"):
                file_path = os.path.join(root, file)
                cmd = "otool -oV " + file_path + " | grep -i __TEXT"
                output = subprocess.check_output(cmd, shell=True)
                if output:
                    pic_libs.append(file_path)
    return pic_libs

def find_failed_libs(path):
    """
    Finds all the libraries that are compiled with ARC, stack canary and PIC
    """
    arc_libs = find_arc(path)
    stack_canary_libs = find_stack_canary(path)
    pic_libs = find_pic(path)
    failed_libs = []
    for lib in arc_libs:
        if lib in stack_canary_libs and lib in pic_libs:
            failed_libs.append(lib)
    return failed_libs

def find_stack_smashing_libs(path):
    """
    Finds all the libraries that are compiled with stack smashing
    """
    stack_smashing_libs = []
    for root, dirs, files in os.walk(path):
        for file in files:
            if file.endswith(".a"):
                file_path = os.path.join(root, file)
                cmd = "otool -oV " + file_path + " | grep -i __stack_chk_guard"
                output = subprocess.check_output(cmd, shell=True)
                if output:
                    stack_smashing_libs.append(file_path)
    return stack_smashing_libs

def main():
    """
    Main function
    """
    if len(sys.argv) != 2:
        print ("Usage: python find_libs.py <path>")
        sys.exit(1)
    path = sys.argv[1]
    failed_libs = find_failed_libs(path)
    stack_smashing_libs = find_stack_smashing_libs(path)
    print("Failed libraries:")
    for lib in failed_libs:
        print (lib)
    print ("Stack smashing libraries:")
    for lib in stack_smashing_libs:
        print (lib)

if __name__ == "__main__":
    main()
