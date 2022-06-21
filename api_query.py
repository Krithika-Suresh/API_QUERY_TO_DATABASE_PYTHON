from multiprocessing import connection
import requests
import os
from dotenv import load_dotenv
from pprint import pprint as pp
import mysql.connector
#'https://otx.alienvault.com'

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

######################################################################

# LOOP TO ACCESS INDIVIDUAL DATA AND INSERT IT INTO THE CORRESPONDING TABLES

len_data = len(data_json["results"])
for data in range(len_data):
    x = data_json["results"][data]
    data_tuple = (x["id"], x["name"], x["description"], x["author_name"], x["modified"], x["created"])
    # print(data_tuple, end = '\n')
    mycursor.execute(insert_query,data_tuple)
    
    
    len_indicators = len(x["indicators"])
    # print(len_indicators)
    for indicator in range(len_indicators):
        indicators = x["indicators"][indicator]
        # print(indicators["id"])
        # print(s, end="\n")
        indicator_tuple = (x["id"], x["name"], indicators["id"], indicators["indicator"], indicators["type"], indicators["created"], indicators["content"], indicators["title"], indicators["description"])
        mycursor.execute(insert_query_indicator,indicator_tuple)
    
    
    len_tags = len(x["tags"])
    for tag in range(len_tags):
        # print(x["tags"][k])
        o = x["tags"][tag]
        tags_tuple = (x["id"], x["name"], o)
        mycursor.execute(insert_query_tags,tags_tuple)


    len_country = len(x["targeted_countries"])
    for country in range(len_country):
        # print(x["targeted_countries"][l])
        w = x["targeted_countries"][country]
        countries_tuple = (x["id"], x["name"], w)
        mycursor.execute(insert_query_countries, countries_tuple)

    len_malware = len(x["malware_families"])
    for malware in range(len_malware):
        # print(x["malware_families"][m])
        n = x["malware_families"][malware]
        malware_tuple = (x["id"], x["name"], n)
        mycursor.execute(insert_query_malware, malware_tuple)

    len_attack = len(x["attack_ids"])
    for attack in range(len_attack):
        # print(x["attack_ids"][p])
        h = x["attack_ids"][attack]
        attack_tuple = (x["id"], x["name"], h)
        mycursor.execute(insert_query_attack, attack_tuple)

    mydb.commit()
print("Done")



