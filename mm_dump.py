'''
Author: Alberto Rodriguez
Date: 14 December 2018
Version: 1.0
In behalf of Champlain College. Masters of Science in Digital Forensics. 

This script parses and displays the contents from a MySQL dump from Mattermost.

To do: 
[+] Parse and display conversations between each user
[+] Determine date stamps and geoIP locations based on IP addresses
[+] Display user logging times
[+] Alphabatize the usernames

Usage: python script.py -i dump_file.sql -o output -l logging.txt 

'''
import argparse     # import standard library argparse for parsing the command line
import binascii     # import standard library binascii to convert binary data to a string
import os           # import standard library os to obtain file details
import hashlib      # import standard library hashlib to perform SHA256 Hashing
import logging      # import standard library logging to record critical actions
import time         # import standard library time conversion functions
import re           # import standard library for regular expressions

def GetChannels(theFile):

    handler2 = open(theFile,'r')
    linecount = 0
    startspot = 0
    endspot = 0
    foundtable = False
    everything = handler2.readlines()
    
    for lines in everything:
        linecount+=1
        if "LOCK TABLES `Channels` WRITE;" in  lines.strip():
            startspot = linecount
        if "40000 ALTER TABLE `Channels` ENABLE KEYS " in lines:
            endspot = linecount
    
    channels = everything[startspot:endspot]
    channels = channels[1]

    channels = channels.strip().split(",")
    r = re.compile(".*-")
    channels = list(filter(r.match, channels))
    final =[]
    for each in channels:
        each = each.lower()
        final.append(each)
        
    return sorted(set(final))

            
      


def GetUsers(theFile):
    handler2 = open(theFile,'r')
    linecount = 0
    startspot = 0
    endspot = 0
    foundtable = False
    everything = handler2.readlines()
    
    for lines in everything:
        linecount+=1
        if "/*!40000 ALTER TABLE `Posts` DISABLE KEYS */;" in  lines.strip():
            startspot = linecount
        if "/*!40000 ALTER TABLE `Posts` ENABLE KEYS */;" in lines:
            endspot = linecount
    
    users = everything[startspot:endspot]
    new = []
    
    users = users[0]
    users = re.findall(r'username\\\":\\\"[a-z]*\\', users)
    
    for each in users:
        each = each.split("\"")
        each = each[2].split("\\\\")
        for each in each:
            each = each.split("\\")
            new.append(each[0])
    new = list(set(new))
    return new
    
    

def ValidateFile(theFile):
    
    ''' Validate the filename theFile
        it must exist and we must have rights
        to read the file.
        raise the appropriate error if either
        is not true
    '''

    # Validate the path exists
    if not os.path.exists(theFile):
        raise argparse.ArgumentTypeError('File does not exist')

    # Validate the path is readable
    if os.access(theFile, os.R_OK):
        return theFile
    else:
        raise argparse.ArgumentTypeError('File is not readable')
#End ValidateFile ===================================
    
#==================================
# Main Script Starts Here
#===================================

if __name__ == '__main__':
    
    
    ''' Specify and Parse the command line, validate the arguments and return results'''
    parser = argparse.ArgumentParser('Mattermost MySQL Database!')
    
    parser.add_argument('-v', '--verbose',    help="specifies to provide useful output of the program", action='store_true')
    parser.add_argument('-i', '--inputFile',  type= ValidateFile, required=True, help="Specify the input file")
    parser.add_argument('-o', '--outputFile', required=True, help="specify the output filename, note the file will be written to the current directory")
    parser.add_argument('-l', '--logFile',    required=True, help="specify the log filename, note the file will be written to the current directory")
    
    args = parser.parse_args()   
    
    if args.verbose:
        VERBOSE = True
    else:
        VERBOSE = FALSE
        
    ''' Extract the in, out and log filenames from the command line'''
    inputFile  = args.inputFile
    outputFile = args.outputFile
    logFile    = args.logFile
     
    
    if VERBOSE:
        print "Mattermost MySQL Database Forensics "
        print "Created by: Arodtube \nDecember 2018\n"
        print "Champlain College - MS in Digital Forensics\n"
        
        print "Input File:  ", inputFile
        print "Output File: ", outputFile
        print "Log File:    ", logFile
        print
    
    
    ''' Attempt to create a log using the user specified log file name
        catch any errors 
    '''
    if VERBOSE:
        print "Creating Log File"
    try:        
        logging.basicConfig(filename=logFile,level=logging.DEBUG,format='%(asctime)s   %(message)s')
    except Exception as err:
        print "LogFile Creation Failed", logFile, err
        quit()
        
    logging.info('Mattermost MySQL Database')

    ''' Perform the needed File I/O 
        1) Obtain the file statistics: file size, last modified time
        2) Obtain the SHA256 Digest of the file
        3) Obtain the first 32 bytes of the file and convert to readable
           Hex ASCII format
    '''
    try:
        if VERBOSE:
            print "Extracting File Stats ..."
        stats        = os.stat(inputFile)      # Read the file stats
        fileSize     = stats.st_size              # extract the file size
        lastModified = stats.st_mtime             # extract the last modified time    
        modifiedTimeStr = time.ctime(lastModified)
        
        logging.info("File: "+inputFile+" Read the file stats Sucess")
        

        
        # Attempt to open the input file
        if VERBOSE:
            print "Opening the Input File ..."        
        with open(inputFile, 'rb') as inFile:
            
            logging.info("File: "+inputFile+" Open File Success")
            sha256 = hashlib.sha256()
            if VERBOSE:
                print "Reading the Input File Contents ..."   
                
            fileContents = inFile.read()
            logging.info("File: "+inputFile+" File Contents Read Success")
            
            if VERBOSE:
                print "Hashing the File Contents - SHA256 ..."            
            sha256.update(fileContents)
            hexDigest = sha256.hexdigest()
            logging.info("File: "+inputFile+" SHA256: "+hexDigest)

            if VERBOSE:
                print "Reading the first 32 bytes of the file ..."
            inFile.seek(0,0)            # Move the file pointer back to the beginning
            header = inFile.read(56)    # Read the first 56 bytes of the file as ASCII
        
            logging.info("File: "+inputFile+" Header Read: "+header)
            
    except Exception as err:
        print "File I/O Error:", inputFile, err
        logging.error("File I/O Error: "+inputFile+": "+err)
        quit()
        
    
    try:
        ''' Create the output file and write the results '''
        if VERBOSE:
            print "Creating the Output File and Recording the Results ..."  
            
# ******************** MATTERMOST ****************
            
            # Gathering Mattermost Channels   
            channels = GetChannels(inputFile)
            print "\n[+] Gathering all channels in this MySQL Database" 
            
            # Gather Mattermost Users
            users = GetUsers(inputFile)
            print "\n[+] Gathering all users in the MySQL Database"
                                                                 
 # ******************** MATTERMOST ****************
 
        with open(outputFile, 'w') as outFile:
            outFile.write("File Name:     "+inputFile+"\n")
            outFile.write("File Size:     "+str(fileSize)+"\n")
            outFile.write("Last Modified: "+modifiedTimeStr+"\n")
            outFile.write("SHA256 Hash:   "+hexDigest+"\n")
            outFile.write("File Header:   "+header+"\n")
            outFile.write("[+] Channels in MySQL Database:  \n")
            for each in channels:
                outFile.write(each+"\n")
            outFile.write("\n[+] Mattermost Users: \n")
            for each in users:
                outFile.write(each+"\n")
                
            
    except Exception as err:
        print "File I/O Error: ", outputFile, err
        logging.error("File I/O Error: "+outputFile+": "+str(err))

    if VERBOSE:
        print "\nScript Complete"    
    
        
