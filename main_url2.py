import requests
import json
import csv
import time
from ratelimit import limits, sleep_and_retry
from datetime import datetime
import sys

headers = {'accept': 'application/json', 'Authorization': '4bd2d893d5156c47b23bf2df8d25254860d97b881405f0569ba4538ac06d2215'}
# headers = {'accept': 'application/json', 'Authorization': 'eb1aa2d4802f281b3ee697819cf497ba71eebefca91bb5fd9dae25270f325301'}

CALLS = 16
RATE_LIMIT = 60
@sleep_and_retry
@limits(calls=CALLS, period=RATE_LIMIT)
def check_limit():
    return


# def otx_api_url_response(url_id, report_id, url,general_csv,url_list_csv,malware_csv,main_csv):
def otx_api_url_response(url_id, report_id, url, general_csv, malware_csv, main_csv):
    check_limit()
    print("_____________")
    print("Currently on these values: ",url_id, report_id, url)

    #general api call
    api_response_general = 'https://otx.alienvault.com/api/v1/indicators/domain/' + url + '/general'
    response_general = requests.get(api_response_general, headers=headers)

    #check for potential errors
    if response_general.status_code != 200:
        print("Status Code Error: ",response_general.status_code,report_id,url_id,url)
        # return ["general",response_general.status_code,report_id,url_id,url]

    if response_general.status_code == 429:
        print("Status Code Error 429: ", response_general.status_code, report_id, url_id, url)
        # return ["general", url_id, report_id, url]
        sys.exit()

    if response_general.status_code == 502 or response_general.status_code == 504:
        print("Status Code Error 502 or 504: ", response_general.status_code, report_id, url_id, url)
        # return ["general", url_id, report_id, url]

    results_general = response_general.json()
    print(results_general)

    # malware api call
    api_response_malware = 'https://otx.alienvault.com/api/v1/indicators/domain/' + url + '/malware'
    response_malware = requests.get(api_response_malware, headers=headers)

    # check for potential errors
    if response_malware.status_code != 200:
        print("Status Code Error: ", response_malware.status_code, report_id, url_id, url)
        # return ["malware", url_id, report_id, url]

    if response_malware.status_code == 429:
        print("Status Code Error 429: ", response_malware.status_code, report_id, url_id, url)
        # return ["malware", url_id, report_id, url]
        sys.exit()

    if response_malware.status_code == 502 or response_malware.status_code == 504:
        print("Status Code Error 502 or 504: ", response_malware.status_code, report_id, url_id, url)
        # return ["malware", url_id, report_id, url]

    results_malware = response_malware.json()
    print(results_malware)

    #Writing locally to json files
    with open(f'/Users/maxnguyen/PycharmProjects/OTX_Api_Test/data/response_output/url/url_general/{url_id}_{report_id}_{url}.json','w') as f:
            try:
                f.write(json.dumps(results_general, sort_keys=False, indent=4))
            except:
                return ["writing to json didn't work", [type, report_id, url_id, url]]

    with open(f'/Users/maxnguyen/PycharmProjects/OTX_Api_Test/data/response_output/url/url_malware/{url_id}_{report_id}_{url}.json','w') as f:
            try:
                f.write(json.dumps(results_malware, sort_keys=False, indent=4))
            except:
                return ["writing to json didn't work", [type, report_id, url_id, url]]

    # Writing to general csv
    with open(general_csv, 'a+', newline='') as csvfile:
        writer = csv.writer(csvfile)
        row = [url_id,report_id,url]

        pulses_num = results_general['pulse_info']['count']
        row.append(pulses_num)  # adds num of pulses

        if pulses_num > 0:
            for w in results_general['pulse_info']['pulses']:
                row2 = row.copy()

                row2.append(w['id'])  # adds individual pulse id
                row2.append(w['created'][:10])  # adds pulse creation date
                row2.append(w['modified'][:10])  # adds pulse modification date
                writer.writerow(row2)
        else:
            row.append("Na")
            row.append("Na")
            row.append("Na")
            writer.writerow(row)

    #writing to malware csv
    with open(malware_csv, 'a+', newline='') as csvfile:
        writer2 = csv.writer(csvfile)
        row = [url_id,report_id,url]
        row.append(results_malware['count']) #adds num of malwares

        if results_malware['count'] > 0:
            for i in results_malware['data']:
                row2 = row.copy()

                row2.append(i['hash']) #adds individual hash value
                row2.append(datetime.utcfromtimestamp(i['datetime_int']).strftime('%Y-%m-%d')) #adds hash time

                if i['detections']['avast'] != None: #adds if avast was detected
                    row2.append(i['detections']['avast'])
                else:
                    row2.append('NOT DETECTED')

                if i['detections']['avg'] != None:#adds if avg was detected
                    row2.append(i['detections']['avg'])
                else:
                    row2.append('NOT DETECTED')

                if i['detections']['clamav'] != None:#adds if clamav was detected
                    row2.append(i['detections']['clamav'])
                else:
                    row2.append('NOT DETECTED')

                if i['detections']['msdefender'] != None:#adds if msdefender was detected
                    row2.append(i['detections']['msdefender'])
                else:
                    row2.append('NOT DETECTED')
                writer2.writerow(row2)

        else:
            row.append("Na")
            row.append("Na")
            row.append("Na")
            row.append("Na")
            row.append("Na")
            row.append("Na")
            writer2.writerow(row)

    #writing to main csv
    with open(main_csv, 'a+', newline='') as csvfile:
        writer = csv.writer(csvfile)

        row = [url_id,report_id,url]

        #general data
        pulses_num = results_general['pulse_info']['count'] #adds pulse count
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

            row.append(smallest_date) #adds earliest pulse data
        else:
            row.append("NA")

        #malware data
        row.append(results_malware['count']) #adds num of malwares

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

            row.append(smallest_date) #adds earliest malware date
            row.append(largest_date) #adds recentmost malware date
        else:
            row.append("NA")
            row.append("NA")


        writer.writerow(row)

# #writes title/headers for csv files
# def csv_setup(general_csv,url_list_csv,malware_csv,main_csv):
#     # CSV writing to compile all data from general
#
#     # general csv file
#     general_fields = ['report_id', 'url_id', 'url', 'pulses', 'pulse_id', 'pulse_creation_date',
#                       'pulse_modification_date']
#     with open(general_csv, 'w', newline='') as csvfile:
#         writer = csv.writer(csvfile)
#         writer.writerow(general_fields)
#
#     # url_list csv file
#     url_list_fields = ['report id', 'url_id', 'url', 'total_urls', 'url', 'date']
#     with open(url_list_csv, 'w', newline='') as csvfile:
#         writer1 = csv.writer(csvfile)
#         writer1.writerow(url_list_fields)
#
#     # malware csv file
#     malware_fields = ['report id', 'url_id', 'url', 'total malwares', 'hash_value', 'datetime', 'avast',
#                       'avg', 'clamav', 'msdefender']
#     with open(malware_csv, 'w', newline='') as csvfile:
#         writer2 = csv.writer(csvfile)
#         writer2.writerow(malware_fields)
#
#     # main csv file (has more general data from all the different api calls
#     main_fields = ['report_id', 'url_id', 'url', 'pulses', 'earliest_pulses_datetime',
#                    'total_malwares', 'earliest_malware_datetime', 'recentmost_malware_datetime', 'total_urls',
#                    'earliest_url_datetime', 'recentmost_url_datetime']
#     with open(main_csv, 'w', newline='') as csvfile:
#         writer3 = csv.writer(csvfile)
#         writer3.writerow(main_fields)

# #used for converting txt files to lists. Not needed.
# def convert_txt_to_list(filename):
#     list_of_hashes_and_values = []
#
#     with open(filename,'r') as f:
#         lines = f.readlines()
#
#         for line in lines:
#             processing_string = line
#             processing_string = processing_string.replace(" ", "")
#             processing_string = processing_string.replace("\n", "")
#             processing_string = processing_string.strip("|")
#             processing_string = processing_string.split("|")
#             list_of_hashes_and_values.append(processing_string)
#
#     return list_of_hashes_and_values

error_list_502_504 = []

def run():
    for i in list_of_urls[1:5000]:
        try:
            otx_api_url_response(i[0], i[1], i[2],
                                 "/Users/maxnguyen/PycharmProjects/OTX_Api_Test/data/results/url/url_general.csv",
                                 "/Users/maxnguyen/PycharmProjects/OTX_Api_Test/data/results/url/url_malware.csv",
                                 "/Users/maxnguyen/PycharmProjects/OTX_Api_Test/data/results/url/url_main.csv")
        except:
            print("except is happening",i)
            error_list_502_504.append(i)
    print(error_list_502_504)

run()