import requests
import json
import csv
from datetime import datetime
import time
headers = {
    'accept': 'application/json',
    'Authorization': '4bd2d893d5156c47b23bf2df8d25254860d97b881405f0569ba4538ac06d2215',
}

'''
Comments for use: 
Compile ips(and report id and ip id) into a list called ip_list. Code will call the OTX api then write the json files locally as well as compile json data into a csv file. 
'''



def main():
    # parse through hashes txt file and create a list of values needed. Not needed for Kia.
    ip_list = convert_txt_to_list('/Users/maxnguyen/PycharmProjects/OTX_Api_Test/data/input/ips.txt')

    error_ips = []

    #adds the titles for the columns in the csv files. Not 100% necessary for adding to database but will help when looking at data.
    csv_title_formatter('/Users/maxnguyen/PycharmProjects/OTX_Api_Test/data/results/ip/ip_general_pulses.csv','/Users/maxnguyen/PycharmProjects/OTX_Api_Test/data/results/ip/ip_url_list.csv','/Users/maxnguyen/PycharmProjects/OTX_Api_Test/data/results/ip/ip_malware.csv','/Users/maxnguyen/PycharmProjects/OTX_Api_Test/data/results/ip/ip_main.csv')

    for i in ip_list:
        api_returned = otx_ip_analysis(i[0], i[1], i[2],'/Users/maxnguyen/PycharmProjects/OTX_Api_Test/data/results/ip/ip_general_pulses.csv','/Users/maxnguyen/PycharmProjects/OTX_Api_Test/data/results/ip/ip_url_list.csv','/Users/maxnguyen/PycharmProjects/OTX_Api_Test/data/results/ip/ip_malware.csv','/Users/maxnguyen/PycharmProjects/OTX_Api_Test/data/results/ip/ip_main.csv')
        if api_returned:
            error_ips.append(api_returned)
            print("Error ips: ", error_ips)

def otx_ip_analysis(ip_id, report_id, ip,general_csv,url_list_csv,malware_csv,main_csv):
    # Calling OTX for general
    url_ip_general = 'https://otx.alienvault.com/api/v1/indicators/IPv4/' + ip + '/general'
    response_general = requests.get(url_ip_general, headers=headers)
    # check for potential errors
    if response_general.status_code != 200:
        return ["status code error", ["general", response_general.status_code, ip_id, report_id, ip]]
    #change written files to have report id and ip/hash id
    results_general = response_general.json()
    print(results_general)

    # Calling OTX for malware
    url_ip_malware = 'https://otx.alienvault.com/api/v1/indicators/IPv4/' + ip + '/malware'
    response_malware = requests.get(url_ip_malware, headers=headers)
    # check for potential errors
    if response_malware.status_code != 200:
        return ["status code error", ["malware", response_malware.status_code, ip_id, report_id, ip]]
    # change written files to have report id and ip/hash id
    results_malware = response_malware.json()
    print(results_malware)

    # Calling OTX for url list
    url_ip_url_list = 'https://otx.alienvault.com/api/v1/indicators/IPv4/' + ip + '/url_list'
    response_url_list = requests.get(url_ip_url_list, headers=headers)
    # check for potential errors
    if response_url_list.status_code != 200:
        return ["status code error", ["url_list", response_url_list.status_code, ip_id, report_id, ip]]
    # change written files to have report id and ip/hash id
    results_url_list = response_url_list.json()
    print(results_url_list)

    #writing json files locally
    with open(f'/Users/maxnguyen/PycharmProjects/OTX_Api_Test/data/response_output/ip/general/{ip_id}_{report_id}_{ip}.json','w') as f:
        try:
            f.write(json.dumps(results_general, sort_keys=False, indent=4))
        except:
            return ["writing to json didn't work", ["general", ip_id, report_id, ip]]

    with open(f'/Users/maxnguyen/PycharmProjects/OTX_Api_Test/data/response_output/ip/malware/{ip_id}_{report_id}_{ip}.json','w') as f:
        try:
            f.write(json.dumps(results_malware, sort_keys=False, indent=4))
        except:
            return ["writing to json didn't work", ["malware", ip_id, report_id, ip]]

    with open(f'/Users/maxnguyen/PycharmProjects/OTX_Api_Test/data/response_output/ip/url_list/{ip_id}_{report_id}_{ip}.json','w') as f:
        try:
            f.write(json.dumps(results_url_list, sort_keys=False, indent=4))
        except:
            return ["writing to json didn't work", ["url_list", ip_id, report_id, ip]]

    #Adding to general csv file
    with open(general_csv, 'a+', newline='') as csvfile:
        writer = csv.writer(csvfile)

        row = [ip_id,report_id,ip]
        row.append(results_general['reputation'])
        row.append(results_general['pulse_info']['count'])

        if results_general['pulse_info']['count'] > 0:
            for i in results_general['pulse_info']['pulses']:
                row2 = row.copy()

                row2.append(i['id'])
                row2.append(i['created'][:10])
                row2.append(i['modified'][:10])
                writer.writerow(row2)
        else:
            row.append("NA")
            row.append("NA")
            row.append("NA")
            writer.writerow(row)


    # Adding to url list csv file
    with open(url_list_csv, 'a+', newline='') as csvfile:
        writer = csv.writer(csvfile)

        row = [report_id,ip_id,ip]

        row.append(results_url_list['full_size'])

        if results_url_list['full_size'] > 0:
            for i in results_url_list['url_list']:
                row2 = row.copy()
                row2.append(i['url'])
                row2.append(i['date'][:10])
                writer.writerow(row2)
        else:
            row.append("NA")
            row.append("NA")
            writer.writerow(row)


    #Adding to malware csv file
    with open(malware_csv, 'a+', newline='') as csvfile:
        writer = csv.writer(csvfile)

        row = [report_id,ip_id,ip]
        row.append(results_malware['count'])

        if results_malware['count'] > 0:
            for i in results_malware['data']:
                row2 = row.copy()
                row2.append(i['hash'])
                row2.append(datetime.utcfromtimestamp(i['datetime_int']).strftime('%Y-%m-%d'))

                if i['detections']['avast'] != None:
                    row2.append(i['detections']['avast'])
                else:
                    row2.append('NOT DETECTED')

                if i['detections']['avg'] != None:
                    row2.append(i['detections']['avg'])
                else:
                    row2.append('NOT DETECTED')

                if i['detections']['clamav'] != None:
                    row2.append(i['detections']['clamav'])
                else:
                    row2.append('NOT DETECTED')

                if i['detections']['msdefender'] != None:
                    row2.append(i['detections']['msdefender'])
                else:
                    row2.append('NOT DETECTED')

                writer.writerow(row2)
        else:
            row.append("NA")
            row.append("NA")
            row.append("NA")
            row.append("NA")
            row.append("NA")
            row.append("NA")
            writer.writerow(row)


    #Adding to main csv file
    with open(main_csv, 'a+', newline='') as csvfile:
        writer = csv.writer(csvfile)
        row = [report_id,ip_id,ip]

        #general data
        row.append(results_general['reputation'])
        pulses_num = results_general['pulse_info']['count']
        row.append(pulses_num)

        if pulses_num > 0:
            smallest_date = results_general['pulse_info']['pulses'][0]['created'][:10]
            formatted_date1 = time.strptime(smallest_date, "%Y-%m-%d")

            for w in results_general['pulse_info']['pulses']:
                checking_date = w['created'][:10]
                formatted_date2 = time.strptime(checking_date, "%Y-%m-%d")

                if formatted_date2 < formatted_date1:
                    smallest_date = checking_date
                    formatted_date1 = formatted_date2

            row.append(smallest_date)
        else:
            row.append("NA")

        #malware data
        row.append(results_malware['count'])

        if results_malware['count'] > 0:
            smallest_date = results_malware['data'][0]['date'][:10]
            formatted_smallest_date = time.strptime(smallest_date, "%Y-%m-%d")

            largest_date = results_malware['data'][0]['date'][:10]
            formatted_largest_date = time.strptime(smallest_date, "%Y-%m-%d")

            for z in results_malware['data']:
                checking_date = z['date'][:10]
                formatted_checking_date = time.strptime(checking_date, "%Y-%m-%d")

                if formatted_checking_date < formatted_smallest_date:
                    smallest_date = checking_date
                    formatted_smallest_date = formatted_checking_date

                if formatted_checking_date > formatted_largest_date:
                    largest_date = checking_date
                    formatted_largest_date = formatted_checking_date

            row.append(smallest_date)
            row.append(largest_date)
        else:
            row.append("NA")
            row.append("NA")

        #url_list_data
        row.append(results_url_list['actual_size'])

        if results_url_list['actual_size'] > 0:
            smallest_date = results_url_list['url_list'][0]['date'][:10]
            formatted_smallest_date = time.strptime(smallest_date, "%Y-%m-%d")

            largest_date = results_url_list['url_list'][0]['date'][:10]
            formatted_largest_date = time.strptime(smallest_date, "%Y-%m-%d")

            for v in results_url_list['url_list']:
                checking_date = v['date'][:10]
                formatted_checking_date = time.strptime(checking_date, "%Y-%m-%d")

                if formatted_checking_date < formatted_smallest_date:
                    smallest_date = checking_date
                    formatted_smallest_date = formatted_checking_date

                if formatted_checking_date > formatted_largest_date:
                    largest_date = checking_date
                    formatted_largest_date = formatted_checking_date
            row.append(smallest_date)
            row.append(largest_date)
        else:
            row.append("NA")
            row.append("NA")

        writer.writerow(row)


#adds in titles for the csv files
def csv_title_formatter(general_csv,url_list_csv,malware_csv,main_csv):
    # CSV writing to compile all data from general

    #general csv file
    general_fields = ['report_id', 'ip_id', 'ip', 'reputation', 'pulses', 'pulse_id', 'pulse_creation_date','pulse_modification_date']
    with open(general_csv, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(general_fields)

    # url_list csv file
    url_list_fields = ['report id', 'ip_id', 'ip', 'total_urls', 'url', 'date']
    with open(url_list_csv, 'w', newline='') as csvfile:
        writer1 = csv.writer(csvfile)
        writer1.writerow(url_list_fields)

    #malware csv file
    malware_fields = ['report id', 'ip_id', 'ip', 'total malwares', 'hash_value', 'datetime', 'avast','avg', 'clamav', 'msdefender']
    with open(malware_csv, 'w', newline='') as csvfile:
        writer2 = csv.writer(csvfile)
        writer2.writerow(malware_fields)

    # main csv file (has more general data from all the different api calls
    main_fields = ['report_id', 'ip_id', 'ip', 'reputation', 'pulses', 'earliest_pulses_datetime',
                   'total_malwares', 'earliest_malware_datetime', 'recentmost_malware_datetime', 'total_urls',
                   'earliest_url_datetime', 'recentmost_url_datetime']
    with open(main_csv, 'w', newline='') as csvfile:
        writer3 = csv.writer(csvfile)
        writer3.writerow(main_fields)


#Used for parsing through the database data to get a list of ips. Not needed for Kia
def convert_txt_to_list(filename):
    list_of_hashes_and_values = []

    with open(filename,'r') as f:
        lines = f.readlines()

        for line in lines:
            processing_string = line
            processing_string = processing_string.replace(" ", "")
            processing_string = processing_string.replace("\n", "")
            processing_string = processing_string.strip("|")
            processing_string = processing_string.split("|")
            list_of_hashes_and_values.append(processing_string)

    return list_of_hashes_and_values

main()