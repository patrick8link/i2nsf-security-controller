import pymongo

# GET IP ADDRESS INFO OF THE NSF
client = pymongo.MongoClient("mongodb://127.0.0.1:27017/")
db = client["nsfDB"]
col = db["capabilities"]
query = {"nsf-name":"firewall"}
res = col.find_one(query)
print(res)