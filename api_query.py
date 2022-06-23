import requests
import os
from dotenv import load_dotenv
from pprint import pprint as pp
import mysql.connector
import time
#'https://otx.alienvault.com'

def api_call(choice):
    # while True:
    load_dotenv()
    APIKEY = os.getenv("API_KEY")
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed?page=1"
    # url = "https://otx.alienvault.com/browse/global/pulses?include_inactive=0&sort=-modified&page=1&limit=10"
    headers = {
        "X-OTX-API-KEY": APIKEY
    }
     ##########################################

    # CONNECTING MYSQL

    mydb = mysql.connector.connect(
        host = "localhost",
        database = "threat_intelligence",
        username = "root",
        password = ""
    )

    mycursor = mydb.cursor()

        ##########################################

        # CONNECTING TO THE WEBSITE USING THE API

    res = requests.get(url, headers = headers)
    data_json = res.json()
    # json_dump = json.dumps(data_json)
    # data_dict = json.loads(json_dump)
    # print(res.status_code)
    # print(data_dict["results"][1])
    # print(len_data, end = '\n')
    # print(data_json.keys())
    # pp(data_json["results"][0]["id"])

        ################################################################################

        #SQL QUERIES TO INSERT INTO TABLE

    insert_query = """INSERT INTO results 
    (PULSE_ID, PULSE_NAME, DESCRIPTION, AUTHOR_NAME, MODIFIED_DATE, CREATED_DATE) VALUES (%s,%s,%s,%s,%s,%s)"""

    insert_query_indicator = """INSERT INTO indicator 
    (PULSE_ID, PULSE_NAME, INDICATOR_ID, INDICATOR, TYPE, CREATED, CONTENT, TITLE, DESCRIPTION) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)"""

    insert_query_tags = """INSERT INTO tags
    (PULSE_ID, PULSE_NAME, TAGS) VALUES (%s,%s,%s)"""

    insert_query_countries = """INSERT INTO targeted_countries
    (PULSE_ID, PULSE_NAME, COUNTRIES) VALUES (%s,%s,%s)"""

    insert_query_malware = """INSERT INTO malware_families
    (PULSE_ID, PULSE_NAME, MALWARE_NAME) VALUES (%s,%s,%s)"""

    insert_query_attack = """INSERT INTO attack_ids
    (PULSE_ID, PULSE_NAME, ATTACK_IDS) VALUES (%s,%s,%s)"""

    select_id_query = """SELECT PULSE_ID FROM results"""
    select_name_query = """SELECT PULSE_NAME FROM results"""

        ######################################################################

    mycursor.execute(select_id_query)
    pulse_ids = mycursor.fetchall()
    # print(pulse_ids)

    mycursor.execute(select_name_query)
    pulse_names = mycursor.fetchall()
    # print(pulse_names)
    # if choice == 1:



        # LOOP TO ACCESS INDIVIDUAL DATA AND INSERT IT INTO THE CORRESPONDING TABLES

    len_data = len(data_json["results"])
    for data in range(len_data):
        results = data_json["results"][data]
        id = (results["id"],)
        name = (results["name"],) 

        if id not in pulse_ids and name not in pulse_names: 
            data_tuple = (results["id"], results["name"], results["description"], results["author_name"], results["modified"], results["created"])
            # print(data_tuple, end = '\n')
            mycursor.execute(insert_query,data_tuple)


            len_indicators = len(results["indicators"])
            # print(len_indicators)
            for indicator in range(len_indicators):
                indicators = results["indicators"][indicator]
                # print(indicators["id"])
                # print(indicators, end="\n")
                indicator_tuple = (results["id"], results["name"], indicators["id"], indicators["indicator"], indicators["type"], indicators["created"], indicators["content"], indicators["title"], indicators["description"])
                mycursor.execute(insert_query_indicator,indicator_tuple)


            len_tags = len(results["tags"])
            for tag in range(len_tags):
                # print(results["tags"][k])
                o = results["tags"][tag]
                tags_tuple = (results["id"], results["name"], o)
                mycursor.execute(insert_query_tags,tags_tuple)


            len_country = len(results["targeted_countries"])
            for country in range(len_country):
                # print(results["targeted_countries"][l])
                w = results["targeted_countries"][country]
                countries_tuple = (results["id"], results["name"], w)
                mycursor.execute(insert_query_countries, countries_tuple)


            len_malware = len(results["malware_families"])
            for malware in range(len_malware):
                # print(results["malware_families"][m])
                n = results["malware_families"][malware]
                malware_tuple = (results["id"], results["name"], n)
                mycursor.execute(insert_query_malware, malware_tuple)


            len_attack = len(results["attack_ids"])
            for attack in range(len_attack):
                # print(results["attack_ids"][p])
                h = results["attack_ids"][attack]
                attack_tuple = (results["id"], results["name"], h)
                mycursor.execute(insert_query_attack, attack_tuple)
            
        mydb.commit()
    print("Done")
    time.sleep(10)
    return(pulse_names)

print("Enter \n1 - To search for a pulse in the database\n2 - To only poll")
choice = int(input())
if choice == 1:
    names = api_call(choice)
    pul_name = (input("Enter the pulse name: "),)
    if pul_name in names:
        print("The given pulse name already exists in the database.")
            
    else:
        print("The pulse name is not in the database")
else:
    while True:
        api_call(choice)
        time.sleep(10)
