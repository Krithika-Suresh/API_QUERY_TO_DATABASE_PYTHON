###################################################################################################################
'''FETCH EPS OF ALL LOG SOURCES AND STORE IT TO MYSQL DATABASE'''
###################################################################################################################

# IMPORING REQUIRED LIBRARIES

from urllib import response
import requests
import mysql.connector
import os
import time
from datetime import datetime
import pandas as pd
from pprint import pprint as pp
from dotenv import load_dotenv

###################################################################################################################

def qradar_dashboard():  
    load_dotenv()
    APIKEY = os.getenv("API_KEY_QRADAR")
    header = {
        "SEC":APIKEY,
        "Accept":'application/json',
    }
###################################################################################################################

#MYSQL CONNECTOR TO DATABASE

    mydb = mysql.connector.connect(
    host = "localhost",
    database = "qradar_dashboard",
    user = "root",
    passwd = ""
    )

    mycursor = mydb.cursor()

    insert_into = "INSERT INTO log_source_eps (Log_source_name, No_of_events_in_interval, EPS_in_interval, Time)VALUES (%s,%s,%s,%s)"

###################################################################################################################

#RESPONSE FROM THE API QUERY

    url_1 = '''https://10.15.50.181/api/ariel/searches?query_expression=SELECT LOGSOURCENAME(logsourceid) AS "Log Source", SUM(eventcount) AS "Number of Events in Interval", SUM(eventcount) / 3600 AS "EPS in Interval" FROM events GROUP BY "Log Source" ORDER BY "EPS in Interval" DESC LAST 60 MINUTES'''
    res = requests.post(url_1, headers=header, verify = False)
    data_json = res.json()
    # pp(data_json)
    search_id = data_json["search_id"]
    # print(search_id)
    # print(res.status_code)
    
    url_2 = "https://10.15.50.181/api/ariel/searches/" + search_id + "/results"
    time.sleep(5)
    
    response = requests.get(url_2, headers=header, verify = False)
    data_json_1 = response.json()
    # pp(data_json_1)
    time_now = datetime.now()
    len_events = len(data_json_1['events'])
    entry_tuple=()
    for i in range(len_events):
        data_json_1['events'][i]["Time"] = time_now
        entry_tuple = (data_json_1['events'][i]["Log Source"], data_json_1['events'][i]["Number of Events in Interval"], data_json_1['events'][i]["EPS in Interval"], data_json_1['events'][i]["Time"])
        mycursor.execute(insert_into, entry_tuple)
    mydb.commit()
    # print(entry_tuple)
    df = pd.DataFrame(data_json_1['events'])
    # print(df)

###################################################################################################################

#INFINITE LOOP

while True:
    qradar_dashboard()
    time.sleep(3600)

###################################################################################################################