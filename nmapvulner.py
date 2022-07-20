# Download CVE-TOOLS from https://github.com/bazaarvoice/cve-tools
# Generate a database (CSV) from a file.
# bin/create-cve-csv -f path/to/file > cves.csv
# %PATH for the script may be changed. Oroginally developed on a Mac,
# %PATH was /Users/
# pip install xmltodict - No point in adding a requirements.txt file to
# this simple tool.

# Felix Alcala dethlocker@0xdeadbeef.ai
# "I am a 10, but on the pH scale; I'm just basic. A simple human. Being."

import datetime
import xmltodict
import re
import os
import getpass
import csv
import sys

time = datetime.datetime.now()

#Use username to derive path, most surefire way to create a consistent path.
user = getpass.getuser()

#Define variables to counter the number of CVE's found
cveCount = 0

#Define variables to identify last results
resultsLog = open('/home/%s/resultsLog.txt' %user, 'a')

#Variables for logging information
xmlPathLog = open('/home/%s/xmlPathLog.txt' %user, 'a')
curDate = time.strftime("%c")

#Variables for printing to resultsLog
xml_file = sys.argv[1]
curIP = sys.argv[2]

#Define path to xml_results file
xml_file_path = '/home/%s/subterfuge/%s' % (user, xml_file)

#Define path to vulnerabilities file
os.chdir('/home/%s/subterfuge/tools/cve-tool' %user)
cveFile = '/home/%s/subterfuge/tools/cve-tool/cve-search/data/exploits.csv' %user

#Define path to save results to
resultsPath = '/home/%s/subterfuge/results/%s.txt' % (user, curIP)
savePath = '/home/%s/subterfuge/results/' %user
saveFile = '%s.txt' % curIP

#Checks to see if XML file path reference exists. If it doesn't, create one.
xmlLogScan = xml_file_path in open('/home/%s/xmlPathLog.txt' %user).read()
xmlPathLog.close()
if xmlLogScan == False:
    xmlPathLog = open('/home/%s/xmlPathLog.txt' %user, 'a')
    xmlPathLog.write(xml_file_path)
    xmlPathLog.write(',')
    xmlPathLog.close()

xmlData = open(xml_file_path)

#Parse the XML file
my_xml = xmltodict.parse(xmlData)
xmlData.close()
os.remove(xml_file_path)

#Open a save results
os.chdir(savePath)
xmlResults = open(saveFile, 'a')

#Checks to see if Nmap even scanned the device.
if 'host' in my_xml['nmaprun']:
    xmlResults.write('Scanned: %s on %s' %(curIP, curDate))
    xmlResults.write('\n')
    xmlResults.write('\n')
    xmlResults.write('\n')

    xmlResults.write('Found services: ')
    xmlResults.write('\n')

    host = my_xml['nmaprun']['host']
    for f in host:
        #Get port info for each host scanned
        results = my_xml['nmaprun']['host'][0]['ports']['port']
        for r in results:
            service = r['service']['@name']
            port = r['@portid']
            protocol = r['@protocol']
            service_version = r['service']['@version']
            forcv = str(service)

            #Strip service string to search for vulnerabilites
            forcv = forcv.replace(" ", "_")
            forcv = forcv.replace("'", "")
            forcv = forcv.replace("-", "_")
            lb = str(protocol + ":" + port + " " + service_version)
            lb = re.sub(' +',' ',lb)
            xmlResults.write("%-30s " % lb)
            xmlResults.write("%-40s " % service)
            if (forcv != 'Service_detection_performance_hit'):
                #Check to see if the service is defined in the vulnerabilities.csv file
                cveSearch = forcv in open(cveFile).read()
                if (cveSearch == True):
                    #Write out that the service has a CVE available
                    xmlResults.write("Potential CVE(s) found")
                    xmlResults.write("\n")
                    cveCount = cveCount + 1
                else:
                    #Write out that the service has no CVE
                    xmlResults.write("No CVE's found")
                    xmlResults.write("\n")
            else:
                #Special handling for Service Detection Performance hit
                xmlResults.write("NO CVE(s) found")
                xmlResults.write("\n")

    if cveCount > 0:
        xmlResults.write("CVE(s) found for " + str(cveCount) + " vulnerability(ies)")
        xmlResults.write("\n")
    else:
        xmlResults.write("No CVE's found in open ports")

    xmlResults.write("\n")
    xmlResults.write("\n")
    xmlResults.write("\n")
    xmlResults.write("\n")

    #Check for OS Detection
    os = my_xml['nmaprun']['host'][0]['os']['osmatch']
    count = 0
    if os:
        if not isinstance(os, list):
            os = [os]

        xmlResults.write("OS Detection results: ")
        xmlResults.write("\n")

        for o in os:
            fos = os[count]['@name']
            xmlResults.write("%-80s" % fos)
            xmlResults.write("\n")
            count = count + 1
else:
    #Write to the results file that the device did not respond.
    xmlResults.write('This device did not respond to our scan')
    xmlResults.write('\n')
    xmlResults.write('\n')
    xmlResults.write('\n')

xmlResults.close()


#Check to see if file was scanned before
resultsPathLogScan = resultsPath in open('/home/%s/resultsLog.txt' %user).read()
resultsPathLogScan = resultsPathLogScan.replace('\n', '')
resultsPathLogScan = resultsPathLogScan.replace('\r', '')

#Get the contents of resultsLog, clean it up, and put it back into the file.
resultsLog = open('/home/%s/resultsLog.txt' %user, 'r')
oldResults = resultsLog.read()
resultsLog.close()

resultsLog = open('/home/%s/resultsLog.txt' %user, 'w')
oldResults = oldResults.replace('\n', '')
oldResults = oldResults.replace('\r', '')
oldResults = oldResults + ',' + resultsPath
resultsLog.write(oldResults)
resultsLog.write('\n')
resultsLog.close()

print('XML parsed')
