import requests
import os
from dotenv import load_dotenv
from pprint import pprint as pp
import mysql.connector
import time
#'https://otx.alienvault.com'

def api_call(page_number = 1):
    # while True:
    load_dotenv()
    # global page_number
    
    APIKEY = os.getenv("API_KEY")
    url = "https://otx.alienvault.com/api/v1/pulses/subscribed?page="+str(page_number)
    # url = "https://otx.alienvault.com/browse/global/pulses?include_inactive=0&sort=-modified&page=1&limit=10"
    headers = {
        "X-OTX-API-KEY": APIKEY
    }
    ##########################################

        # CONNECTING TO THE WEBSITE USING THE API

    res = requests.get(url, headers = headers)
    data_json = res.json()
    # print(page_number)
    # json_dump = json.dumps(data_json)
    # data_dict = json.loads(json_dump)
    # print(res.status_code)
    # print(data_dict["results"][1])
    # print(len_data, end = '\n')
    # print(data_json.keys())
    # pp(data_json["results"][0]["id"])

    data_fetching(data_json, page_number)

    ################################################################################

def data_fetching(data_json, page_number):

    import mysql.connector

     ##########################################

    # CONNECTING MYSQL

    mydb = mysql.connector.connect(
        host = "localhost",
        database = "threat_intelligence",
        username = "root",
        password = ""
    )

    mycursor = mydb.cursor()

        

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

    create_table = """CREATE TABLE IF NOT EXISTS {} (PULSE_ID CHAR(24), PULSE_NAME VARCHAR(100), INDICATOR_ID VARCHAR(35) PRIMARY KEY, INDICATOR_VALUE VARCHAR(40))"""
    ######################################################################

    mycursor.execute(select_id_query)
    pulse_ids = mycursor.fetchall()
    # print(pulse_ids)

    mycursor.execute(select_name_query)
    pulse_names = mycursor.fetchall()
    # print(pulse_names)
    d = {}
    indicator_id = set() 
    lst_indicator_types=set()
    len_data = len(data_json["results"])
    # print("Data length: ",len_data)
    while len_data!=0:
        # print('inside')
        for data in range(len_data):
            # print(page_number)
            results = data_json["results"][data]
            id = (results["id"],)
            name = (results["name"],)   
            len_indicators = len(results["indicators"])

##############################################################################################

# CODE TO FIND THE TYPES OF IDs AND THE NUMBERS

        #     for indicator in range(len_indicators):
        #         indicators = results["indicators"][indicator]
        #         if indicators["type"] not in d:
        #             d[indicators["type"]]=1
        #         else:
        #             d[indicators["type"]]+=1
        # print(d)

##############################################################################################

# ADDING DATA INTO THE DATABASE
            if id not in pulse_ids and name not in pulse_names: 
                len_indicators = len(results["indicators"])
                data_tuple = (results["id"], results["name"], results["description"], results["author_name"], results["modified"], results["created"])
                mycursor.execute(insert_query,data_tuple)
                len_indicators = len(results["indicators"])
                for indicator in range(len_indicators):
                    indicators = results["indicators"][indicator]
                    lst_indicator_types.add(indicators["type"])

                      # print(indicator_id)
                    l = str(indicators["type"]).split('-')                
                    if len(l)==2:
                        indicators_name = l[0]+l[1]
                        sql = create_table.format(str(indicators_name))
                        mycursor.execute(sql)
                        if indicators["id"] not in indicator_id:
                            id_details = [results["id"], results["name"], indicators["id"], indicators["indicator"]]
                            table_name = str(indicators_name)
                            insert_indicator = "INSERT IGNORE INTO " + table_name + " VALUES (%s,%s,%s,%s)"
                            # print(insert_indicator)
                            mycursor.execute(insert_indicator, id_details)
                    else:
                        sql = create_table.format(str(indicators["type"]))
                        mycursor.execute(sql)
                        id_details = [results["id"], results["name"], indicators["id"], indicators["indicator"]]
                        if indicators["id"] not in indicator_id:
                            table_name = indicators["type"]
                            insert_indicator = "INSERT INTO " + table_name + " VALUES (%s,%s,%s,%s)"
                            # print(insert_indicator)
                            mycursor.execute(insert_indicator, id_details)
                    indicator_id.add(indicators["id"])
                        # print(sql)
                        # print("Done")
                    indicator_id.add(indicators["id"])
                    indicator_tuple = (results["id"], results["name"], indicators["id"], indicators["indicator"], indicators["type"], indicators["created"], indicators["content"], indicators["title"], indicators["description"])
                    mycursor.execute(insert_query_indicator,indicator_tuple)
                    mydb.commit()
            
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
                # page_number+=1
                # print(page_number)
            # return(pulse_names)
        page_number+=1
        # print(page_number)

# RECURSIVE FUNCTION CALL
        api_call(page_number)
    
   
api_call()