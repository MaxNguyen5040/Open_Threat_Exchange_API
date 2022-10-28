import requests
import json
import csv
import os
import time

'''
Hash sections:
general: General_hashes metadata about the file hash, and a list of the other sections currently available for this hash.
    @Kia: general contains pulses but not AV and sanbox
analysis: dynamic and static analysis of this file (Cuckoo analysis, exiftool, etc.)
    @Kia: analysis contains AV and sanbox info but not pluses 
@ so for general otx hash db we need two queries one general & analysis
'''

headers = {
    'accept': 'application/json',
    'Authorization': '4bd2d893d5156c47b23bf2df8d25254860d97b881405f0569ba4538ac06d2215'}

def main():
    # parse through hashes txt file and create a list of values needed.
    hashes_list = convert_txt_to_list('/Users/maxnguyen/PycharmProjects/OTX_Api_Test/data/input/hashes.txt')
    print(hashes_list)

    #if want code to write json files
    write_to_files = False

    error_hashes = []
    # for i in hashes_list:
    #     general_response = otx_hash_api_response(i[0],i[1],i[2],write_to_files,'general')
    #     analysis_response = otx_hash_api_response(i[0],i[1],i[2],write_to_files,'analysis')
    #
    #     if general_response:
    #         error_hashes.append(general_response)
    #     if analysis_response:
    #         error_hashes.append(analysis_response)

    if error_hashes != []:
        print("Error hashes:",error_hashes)
        input('move on?')
        #ADD CODE IN FOR WHAT TO DO AFTER WRITE TO CSV - LIKE REDO THESE HASHES

    #add both sets of data to csv
    csv_writer('/Users/maxnguyen/PycharmProjects/OTX_Api_Test/data/response_output/hash/general','/Users/maxnguyen/PycharmProjects/OTX_Api_Test/data/response_output/hash/analysis',
               '/Users/maxnguyen/PycharmProjects/OTX_Api_Test/data/results/hashes/hashes_detections.csv','/Users/maxnguyen/PycharmProjects/OTX_Api_Test/data/results/hashes/hashes_general.csv')

def csv_writer(general_folder,analysis_folder,detections_file_name,general_file_name):

    detections_json_files = [pos_json for pos_json in os.listdir(general_folder)]
    detections_fields = ['number', 'hash_id','report_id','hash', 'pulses', 'sha1', 'ssdeep', 'sha256', 'md5',
              'adobemalwareclassifier', 'apk', 'avast', 'avg', 'clamav', 'cuckoo', 'disa_entrypoint', 'exiftool', 'machoinfo',
              'msdefender','metaextract', 'pe32info', 'peanomal', 'ratdecoder', 'strings', 'yarad', 'zipfiles']

    count = 0
    with open(detections_file_name, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(detections_fields)

        for i in detections_json_files[0:30]:
            row = [count]
            z = i.split("_")
            row += z
            row.pop(-1)

            with open('/Users/maxnguyen/PycharmProjects/OTX_Api_Test/data/response_output/hash/general/' + i) as file:
                data = json.load(file)
                row.append(data['indicator'])
                row.append(data['pulse_info']['count'])


            try:
                with open('/Users/maxnguyen/PycharmProjects/OTX_Api_Test/data/response_output/hash/analysis/' + i) as file2:
                    data = json.load(file2)
                    if data["page_type"] != "generic":
                        row.append(data['analysis']['info']['results']['sha1'])
                        row.append(data['analysis']['info']['results']['ssdeep'])
                        row.append(data['analysis']['info']['results']['sha256'])
                        row.append(data['analysis']['info']['results']['md5'])

                        plugins_names = [k for k, v in data['analysis']['plugins'].items()]
                        print(plugins_names)
                        for w in detections_fields[9:]:
                            if w in plugins_names:
                                if w == "cuckoo":
                                     row.append(len(data['analysis']['plugins'][w]['result'].keys()))
                                elif w == "strings":
                                    row.append(len(data['analysis']['plugins'][w]['results']))
                                elif data['analysis']['plugins'][w]['results'] == None:
                                    row.append('Null Case')
                                else:
                                    row.append(len(data['analysis']['plugins'][w]['results'].keys()))
                            else:
                                row.append("plugin not detected")

                    else: #empty file
                        row += ['NA']*21
                writer.writerow(row)
                count += 1
            except FileNotFoundError:
                pass






    general_fields = ['number','hash_id','report_id','hash','pulses','earliest_pulse_date','recentmost_pulse_date','plugin_amount','analysis_date']

    count = 0

    with open(general_file_name, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(general_fields)

        for i in detections_json_files:
            row = [count]
            z = i.split("_")
            row += z
            row.pop(-1)

            with open('/Users/maxnguyen/PycharmProjects/OTX_Api_Test/data/response_output/hash/general/' + i) as file:
                data = json.load(file)
                row.append(data['indicator'])
                row.append(data['pulse_info']['count'])

                if data['pulse_info']['count'] > 0:
                    smallest_date = data['pulse_info']['pulses'][0]['created'][:10]
                    formatted_smallest_date = time.strptime(smallest_date, "%Y-%m-%d")

                    largest_date = data['pulse_info']['pulses'][0]['created'][:10]
                    formatted_largest_date = time.strptime(smallest_date, "%Y-%m-%d")

                    for b in data['pulse_info']['pulses']:
                        checking_date = b['created'][:10]
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

            try:
                with open('/Users/maxnguyen/PycharmProjects/OTX_Api_Test/data/response_output/hash/analysis/' + i) as file3:
                    data = json.load(file3)
                    if data['analysis'] != {}:
                        row.append(len(data['analysis']['plugins'].items()))
                        row.append(data['analysis']['datetime_int'][0:10])
                    else:
                        row.append("NA")
                        row.append("NA")
            except FileNotFoundError:
                pass

            writer.writerow(row)
            count += 1




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

def otx_hash_api_response(hash_id, report_id, hash,write_files,type):
    #setup
    url = 'https://otx.alienvault.com/api/v1/indicators/file/' + hash + '/'+type
    response = requests.get(url, headers=headers)
    #check for potential errors
    if response.status_code != 200:
        return ["status code error",[type,response.status_code,report_id,hash_id,hash]]

    results = response.json()
    print(results)

    if write_files == True:
        with open(
                    f'/Users/maxnguyen/PycharmProjects/OTX_Api_Test/data/response_output/hash/{type}/{hash_id}_{report_id}_{hash}.json',
                    'w') as f:
                try:
                    f.write(json.dumps(results, sort_keys=False, indent=4))
                except:
                    return ["writing to json didn't work", [type, report_id, hash_id, hash]]

main()