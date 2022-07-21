# -*- coding: utf-8 -*-
###############################################################################################################################################################
# 1. Open AndroidManifest.xml from specified path
# 2. Check to see if AndroidManifest.xml to see if android:allowBackup is set to false matching android:allowBackup=”false” if "true" then print message		  #
# 3. Check to see if AndroidManifest.xml to see if android:debuggable is set to false matching android:debuggable="false" if "true" then print message		  #
# 4. Check AndroidManifest.xml permissions set against https://developer.android.com/reference/android/Manifest.permission.html								  #
# Felix Alcala dethlocker@0xdeadbeef.ai
# "I am a 10, but on the pH scale; I'm just basic. A simple human. Being."
###############################################################################################################################################################
__author__ = "Felix Alcala"
__copyright__ = "Copyleft 2022, Felix Alcala"
__credits__ = ["Felix Alcala"]
__license__ = "GPL"
__version__ = "1.0b"
__maintainer__ = "dethlocker"
__email__ = "dethlocker@0xdeadbeef.ai"
__status__ = "DevSoup"

import sys
import requests
import argparse
import os
import re
import xml.etree.ElementTree as etree
from bs4 import BeautifulSoup
#string to check android:allowBackup in AndroidManifest.xml
F_ALLOWBACKUP_STRING = 'android:allowBackup="true"'
#string to check android:debuggable in AndroidManifest.xml
F_DEBUGGABLE_STRING = 'android:debuggable="true"'
#string to check android:process in AndroidManifest.xml
F_PROCESS_STRING = 'android:process=""'
#string to check android:exported in AndroidManifest.xml
F_EXPORTED_STRING = 'android:exported=""'
#string to check android:name in AndroidManifest.xml
F_NAME_STRING = 'android:name=""'
#string to check android:name in AndroidManifest.xml
F_ENCRYPTED_STRING = 'android:name=""'
#string to check android:testOnly in AndroidManifest.xml
F_TESTONLY_STRING = 'android:testOnly=""'
#string to check android:theme in AndroidManifest.xml
F_THEME_STRING = 'android:theme="'
#string to check android.permission in AndroidManifest.xml
F_PERMISSION_STRING = 'android.permission'
#string to check android.permission in AndroidManifest.xml
F_ALLOW_BACKUP_STRING = 'android:allowBackup="true"'
#string to check android.permission in AndroidManifest.xml
F_ALLOW_DEBUGGABLE_STRING = 'android:debuggable="true"'


#Array that holds the list of permissions
PERMISSIONS_ARRAY = []
#Variable that holds the name of the activity
ACTIVITY_NAME = ""
#Check permission is dangerous or not
DANGEROUS_PERMISSION = ""


def check_where_process_is_running(manifestFilePath):
	"""check to see android:process is set to blank or not

	Args:
		manifestFilePath (str): string that holds the path of AndroidManifest.xml

	Returns:
		boolean: true if android:process is set to blank else false

	"""
	print("\nCheck to see android:process is blank or not:")
	#Open manifest file in read mode
	manifestObj = open(manifestFilePath, 'r')
	#Read manifest file
	manifest = manifestObj.read()
	#Close manifest file
	manifestObj.close()
	#Find string android:process="" in manifest file
	findProcess = re.search(F_PROCESS_STRING, manifest)
	#If findProcess is not NONE then return True
	if findProcess is not None:
		print("\t[+] android:process is blank")
		return True
	#If findProcess is NONE then return False
	else:
		print("\t[-] android:process is set")


def check_where_exported_is_set(manifestFilePath):
	"""check to see android:exported is set or not

	Args:
		manifestFilePath (str): string that holds the path of AndroidManifest.xml

	Returns:
		boolean: true if android:exported  is set else false

	"""
	print("Check to see android:exported is set or not:")
	#Open manifest file in read mode
	manifestObj = open(manifestFilePath, 'r')
	#Read manifest file
	manifest = manifestObj.read()
	#Close manifest file
	manifestObj.close()
	#Find string android:exported="" in manifest file
	findExported = re.search(F_EXPORTED_STRING, manifest)
	#If findExported is not NONE then return True
	if findExported is not None:
		print("\t[+] android:exported is set")
		return True
	#If findExported is NONE then return False
	else:
		print("\t[-] android:exported is not set")


def check_where_name_is_blank(manifestFilePath):
	"""check to see android:name is blank or not

	Args:
		manifestFilePath (str): string that holds the path of AndroidManifest.xml

	Returns:
		boolean: true if android:name is blank else false

	"""
	print("Check to see android:name is blank or not:")
	#Open manifest file in read mode
	manifestObj = open(manifestFilePath, 'r')
	#Read manifest file
	manifest = manifestObj.read()
	#Close manifest file
	manifestObj.close()
	#Find string android:name="" in manifest file
	findName = re.search(F_NAME_STRING, manifest)
	#If findName is not NONE then return True
	if findName is not None:
		print("\t[+] android:name is blank")
		return True
	#If findName is NONE then return False
	else:
		print("\t[-] android:name is not blank")


def check_where_allowBackup_is_true(manifestFilePath):
	"""check to see android:allowBackup is true or not

	Args:
		manifestFilePath (str): string that holds the path of AndroidManifest.xml

	Returns:
		boolean: true if android:allowBackup is true else false

	"""
	print("Check to see android:allowBackup is true or not:")
	#Open manifest file in read mode
	manifestObj = open(manifestFilePath, 'r')
	#Read manifest file
	manifest = manifestObj.read()
	#Close manifest file
	manifestObj.close()
	#Find string android:allowBackup=”true” in manifest file
	findAllowBackup = re.search(F_ALLOW_BACKUP_STRING, manifest)
	#If findAllowBackup is not NONE then return True
	if findAllowBackup is not None:
		print("\t[+] android:allowBackup is true")
		return True
	#If findAllowBackup is NONE then return False
	else:
		print("\t[-] android:allowBackup is not true")


def check_where_testOnly_is_true(manifestFilePath):
	"""check to see android:testOnly is true or not

	Args:
		manifestFilePath (str): string that holds the path of AndroidManifest.xml

	Returns:
		boolean: true if android:testOnly is true else false

	"""
	print("Check to see android:testOnly is true or not:")
	#Open manifest file in read mode
	manifestObj = open(manifestFilePath, 'r')
	#Read manifest file
	manifest = manifestObj.read()
	#Close manifest file
	manifestObj.close()
	#Find string android:testOnly="true" in manifest file
	findTestOnly = re.search(F_TESTONLY_STRING, manifest)
	#If findTestOnly is not NONE then return True
	if findTestOnly is not None:
		print("\t[+] android:testOnly is true")
		return True
	#If findTestOnly is NONE then return False
	else:
		print("\t[-] android:testOnly is not true")


def check_where_debuggable_is_true(manifestFilePath):
	"""check to see android:debuggable is true or not

	Args:
		manifestFilePath (str): string that holds the path of AndroidManifest.xml

	Returns:
		boolean: true if android:debuggable is true else false

	"""
	print("Check to see android:debuggable is true or not:")
	#Open manifest file in read mode
	manifestObj = open(manifestFilePath, 'r')
	#Read manifest file
	manifest = manifestObj.read()
	#Close manifest file
	manifestObj.close()
	#Find string android:debuggable=”true” in manifest file
	findDebugable = re.search(F_ALLOW_DEBUGGABLE_STRING, manifest)
	#If findDebugable is not NONE then return True
	if findDebugable is not None:
		print("\t[+] android:debuggable is true")
		return True
	#If findDebugable is NONE then return False
	else:
		print("\t[-] android:debuggable is not true")


def check_where_theme_is_set(manifestFilePath):
	"""check to see android:theme is set or not

	Args:
		manifestFilePath (str): string that holds the path of AndroidManifest.xml

	Returns:
		boolean: true if android:theme is set else false

	"""
	print("Check to see android:theme is set or not:")
	#Open manifest file in read mode
	manifestObj = open(manifestFilePath, 'r')
	#Read manifest file
	manifest = manifestObj.read()
	#Close manifest file
	manifestObj.close()
	#Find string android:theme in manifest file
	findTheme = re.search(F_THEME_STRING, manifest)
	#If findTheme is not NONE then return True
	if findTheme is not None:
		print("\t[+] android:theme is set")
		return True
	#If findTheme is NONE then return False
	else:
		print("\t[-] android:theme is not set")


def check_where_permission_is_set(manifestFilePath):
	"""check to see android:permission is set or not

	Args:
		manifestFilePath (str): string that holds the path of AndroidManifest.xml

	Returns:
		boolean: true if android:permission is set else false

	"""
	print("Check to see android:permission is set or not:")
	#Open manifest file in read mode
	manifestObj = open(manifestFilePath, 'r')
	#Read manifest file
	manifest = manifestObj.read()
	#Close manifest file
	manifestObj.close()
	#Find string android:permission in manifest file
	findPermission = re.search(F_PERMISSION_STRING, manifest)
	#If findPermission is not NONE then return True
	if findPermission is not None:
		print("\t[+] android:permission is set")
		return True
	#If findPermission is NONE then return False
	else:
		print("\t[-] android:permission is not set")


def check_where_encrypted_is_set(manifestFilePath):
	"""check to see android:encrypted is set to true or false

	Args:
		manifestFilePath (str): string that holds the path of AndroidManifest.xml

	Returns:
		boolean: true if android:encrypted is set to true else false

	"""
	print("Check to see android:encrypted is set or not:")
	#Open manifest file in read mode
	manifestObj = open(manifestFilePath, 'r')
	#Read manifest file
	manifest = manifestObj.read()
	#Close manifest file
	manifestObj.close()
	#Find string android:encrypted in manifest file
	findEncrypted = re.search(F_ENCRYPTED_STRING, manifest)
	#If findEncrypted is not NONE then return True
	if findEncrypted is not None:
		print("\t[+] android:encrypted is set")
		return True
	#If findEncrypted is NONE then return False
	else:
		print("\t[-] android:encrypted is not set")


def get_activities_from_manifest(filePath):
	"""get the activity names from manifest file

	Args:
		filePath (str): string that holds the path of AndroidManifest.xml

	Returns:
		boolean: true if the activity is found else false

	"""
	#Creates dictionary to store activity name and permission
	activityNameAndPermissionDict = {}
	#Creates a tree from the AndroidManifest.xml
	tree = etree.parse(filePath)
	#Finds the root of xml file
	root = tree.getroot()
	#Checks to see if the xml file is corrupted
	if root is not None:
		#Creates a dictionary to store the activity name and permission
		activityNameAndPermissionDict = {}
		#Iterate through the activities(child elements of manifest)
		for each in root.iter('activity'):
			#Create a varibale to store the activity name
			activityName = ""
			#Iterate through the activity(child elements of manifest)
			for activity in each.iter('activity'):
				#Iterate through the activity(child elements of manifest)
				for attrib in activity.attrib:
					#Check to see if attrib = name
					if attrib == "android:name":
						#Store activity name in variable
						activityName = activity.attrib['android:name']
						#Check to see if the activity name is present in the dictionary
						if activityName not in activityNameAndPermissionDict:
							#Creates a dictionary to store the activity name and permission
							activityNameAndPermissionDict = {}
						for activity in each.iter('uses-permission'):
							#Iterate through the activity(child elements of manifest)
							for attrib in activity.attrib:
								#Check to see if attrib = name
								if attrib == "android:name":
									#Store permission name in permission array
									PERMISSIONS_ARRAY.append(activity.attrib['android:name'])
							#Add permission name to dictionary
							activityNameAndPermissionDict[activityName] = PERMISSIONS_ARRAY
							#Creates a dictionary to store the activity name and permission
							activityNameAndPermissionDict = {}
						#Creates a dictionary to store the activity name and permission
						activityNameAndPermissionDict = {}
					#Iterate through the activity(child elements of manifest)
					for activity in each.iter('uses-permission'):
						#Iterate through the activity(child elements of manifest)
						for attrib in activity.attrib:
							#Check to see if attrib = name
							if attrib == "android:name":
								#Store activity name in variable
								activityName = activity.attrib['android:name']
								#Check to see if the activity name is present in the dictionary
								if activityName not in activityNameAndPermissionDict:
									#Creates a dictionary to store the activity name and permission
									activityNameAndPermissionDict = {}
								for activity in each.iter('uses-permission'):
									#Iterate through the activity(child elements of manifest)
									for attrib in activity.attrib:
										#Check to see if attrib = name
										if attrib == "android:name":
											#Store permission name in permission array
											PERMISSIONS_ARRAY.append(activity.attrib['android:name'])
									#Add permission name to dictionary
									activityNameAndPermissionDict[activityName] = PERMISSIONS_ARRAY
									#Creates a dictionary to store the activity name and permission
									activityNameAndPermissionDict = {}
								#Creates a dictionary to store the activity name and permission
								activityNameAndPermissionDict = {}
	#Return the dictionary
	return activityNameAndPermissionDict


def check_activity_is_exported(activityNameAndPermissionDict):
	"""check to see activity is exported or not

	Args:
		activityNameAndPermissionDict (dict): dictionary that holds activity name and permission

	Returns:
		boolean: true if activity is exported else false

	"""
	#Print message
	print("Check to see activity is exported or not:")
	#Iterate through the activity(child elements of manifest)
	for activityName, permission in activityNameAndPermissionDict.items():
		#Iterate through the activity(child elements of manifest)
		for i in range(0, len(permission)):
			#Check to see if permission = android.permission.INTERNET
			if permission[i] == "android.permission.INTERNET":
				print("\t[+] Action: " + activityName + " is exported")
				return True
			else:
				pass
	print("\t[-] Action is not exported")


def check_activity_is_dangerous(activityNameAndPermissionDict):
	"""check to see activity is dangerous or not

	Args:
		activityNameAndPermissionDict (dict): dictionary that holds activity name and permission

	Returns:
		boolean: true if activity is exported else false

	"""
	#Print message
	print("Check to see activity is dangerous or not:")
	#URL that holds the permissions
	url = "https://developer.android.com/reference/android/Manifest.permission.html"
	#Use requests to get the page
	resp = requests.get(url)
	#Check to see if resp is 200
	if resp.status_code == 200:
		#Parse the page
		soup = BeautifulSoup(resp.text, 'lxml')
		#Iterate through the activity(child elements of manifest)
		for activityName, permission in activityNameAndPermissionDict.items():
			#Iterate through the activity(child elements of manifest)
			for i in range(0, len(permission)):
				#Find the permission in the webpage
				divs = soup.find_all("h2", { "name" : permission[i] })
				#Check to see if permission is present
				if divs:
					#Print message
					print("\t[+] Action: " + activityName + " is Dangerous")
					return True
				else:
					pass
		print("\t[-] Action is not dangerous.")
	else:
		print("Something went wrong!")


def main():
	"""take the arguments from command line

	"""
	#Take the argument from the commandline
	parser = argparse.ArgumentParser()
	#Set the path of AndroidManifest.xml as an argument
	parser.add_argument("-p", "--path", help="Absolute path to AndroidManifest.xml")
	#Set the argument as an argument
	args = parser.parse_args()
	#Check to see if AndroidManifest.xml is present
	if os.path.exists(args.path):
		#Check to see android:process is set or not
		check_where_process_is_running(args.path)
		#Check to see android:exported is set or not
		check_where_exported_is_set(args.path)
		#Check to see android:name is blank or not
		check_where_name_is_blank(args.path)
		#Check to see android:allowBackup is true or not
		check_where_allowBackup_is_true(args.path)
		#Check to see android:testOnly is true or not
		check_where_testOnly_is_true(args.path)
		#Check to see android:debuggable is true or not
		check_where_debuggable_is_true(args.path)
		#Check to see android:theme is set or not
		check_where_theme_is_set(args.path)
		#Check to see android:permission is set or not
		check_where_permission_is_set(args.path)
		#Check to see android:encrypted is set or not
		check_where_encrypted_is_set(args.path)
		#Get the activity names from manifest file
		activityNameAndPermissionDict = get_activities_from_manifest(args.path)
		#Check to see if activity is exported or not
		check_activity_is_exported(activityNameAndPermissionDict)
		#Check to see if activity is dangerous or not
		check_activity_is_dangerous(activityNameAndPermissionDict)
	else:
		print("AndroidManifest.xml is not present.")


if __name__ == "__main__":
	# Call main function
	main()
