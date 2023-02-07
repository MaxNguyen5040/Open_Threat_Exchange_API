# Open_Threat_Exchange_API

**Since the main_url.py and main_ip.py are similar to main_hashes.py, the main hashes file has been consolidated with in-depth comments explaining what the program does.**

A Python program to read in any number of Hash values, IP addresses, or URLs that are potentially malicious, developed with mentorship from University of Illinois at Chicago Professor Kiavish (Kia) Satvat. Calls AT&T's Open Threat Exchange API, and processes returned JSON data containing connected malware, communities, and dates. Stores data locally and in a spreadsheet file for ease of viewing. Due to the line by line nature of the program, can process an infinite amount of potentially malicious websites/files, reading, analyzing, and storing any findings in a spreadsheet.

Used to process data to suppport Professor Satvat's research in malware detection platforms/algorithms. 

The "Data" folder holds all input data, a list of Hash values, IP addresses, or URLs that are potentially malicious. 

The "Results" folder holds csv files (spreadsheets) of all generated data after running each input value through the Open Threat Exchange API. Since each input returns different data after being passed to the Open Threat Exchange, input types are separated. 

Each "main_.py" file contains the main method for formatting data, sending that data to the API, and storing it locally. 

