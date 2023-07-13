import pymongo
import netifaces as ni
import sys, getopt
import netifaces as ni
import re
from regex import R
from pprint import pprint
import json
from flask import Flask,request
from bson.json_util import dumps
from flask_cors import CORS
from dict2xml import dict2xml
import generatorv2
import configparser
from flask import Response

from ncclient import manager


config = configparser.ConfigParser()
config.sections()

config.read('../controller.ini')
config.sections()

#print(f"mongodb://127.0.0.1:27017/")


api = Flask(__name__)
CORS(api)

@api.route('/url/get', methods = ['GET'])
def restGetURLGroup():
    query = request.json
    client = pymongo.MongoClient(f"mongodb://127.0.0.1:27017/")
    db = client["endpoint"]
    col = db["url"]
    
    query = {query} #{"name":key}
    res = col.find_one(query)
    
    return json.loads(dumps(res))

@api.route('/url/put', methods = ['PUT'])
def restInsertURLGroup():
    try:
        data = request.json
        print(data)
        client = pymongo.MongoClient(f"mongodb://127.0.0.1:27017/")
        db = client["endpoint"]
        col = db["url"]
        
        res = col.insert_one(data)
        return "Success"
    except pymongo.errors.DuplicateKeyError:
        print("Duplicate Key for ",data["name"])

@api.route('/nsfDB/get', methods = ['GET'])
def restGetAllCapability(query={}):
    client = pymongo.MongoClient(f"mongodb://127.0.0.1:27017/")
    db = client["nsfDB"]
    col = db["capabilities"]
    result = {}
    result["nsf"] = []
    for res in col.find(query):
        result["nsf"].append(res)
    return json.loads(dumps(result))

@api.route('/user/put', methods = ['PUT'])
def restInsertUserGroup():
    try:
        data = request.json
        client = pymongo.MongoClient(f"mongodb://127.0.0.1:27017/")
        db = client["endpoint"]
        col = db["user"]
        
        res = col.insert_one(data)
        return "Success"
    except pymongo.errors.DuplicateKeyError:
        return "Duplicate Key for ",data["name"]
        

@api.route('/device/get', methods = ['GET'])
def restGetDeviceGroup():
    client = pymongo.MongoClient(f"mongodb://127.0.0.1:27017/")
    db = client["endpoint"]
    col = db["device"]
    query = request.json
    res = col.find_one(query)
    return res

@api.route('/device/put', methods = ['PUT'])
def restInsertDeviceGroup():
    try:
        data = request.json
        client = pymongo.MongoClient(f"mongodb://127.0.0.1:27017/")
        db = client["endpoint"]
        col = db["device"]
        
        res = col.insert_one(data)
        return "Success"
    except pymongo.errors.DuplicateKeyError:
        return "Duplicate Key for ",data["name"]
        

@api.route('/user/get', methods = ['GET'])
def restGetUserGroup():
    
    client = pymongo.MongoClient(f"mongodb://127.0.0.1:27017/")
    db = client["endpoint"]
    col = db["user"]
    query = request.json
    res = col.find_one(query)
    return res

@api.route('/location/put', methods = ['PUT'])
def restInsertLocationGroup():
    try:
        data = request.json
        client = pymongo.MongoClient(f"mongodb://127.0.0.1:27017/")
        db = client["endpoint"]
        col = db["location"]
        
        res = col.insert_one(data)
        return "Success"
    except pymongo.errors.DuplicateKeyError:
        print("Duplicate Key for ",data["name"])

@api.route('/location/get', methods = ['GET'])
def restGetLocationGroup():
    client = pymongo.MongoClient(f"mongodb://127.0.0.1:27017/")
    db = client["endpoint"]
    col = db["location"]
    query = request.json
    res = col.find_one(query)
    return res


# Insert Capabilities of an NSF. The DMS delivers the capabilities via Registration Interface
@api.route('/register/nsf', methods = ['PUT'])
def restInsertCapability():
    try:
        data = request.json
        client = pymongo.MongoClient(f"mongodb://127.0.0.1:27017/")
        db = client["nsfDB"]
        col = db["capabilities"]
        print(data)
        res = col.insert_one(data)
        return "Success"
    except pymongo.errors.DuplicateKeyError:
        print("Duplicate Key for ",data["nsf-name"])
        return Response(f"Duplicate Key for {data['nsf-name']}", status=400)


#API for security policy tranlator - Input High-level policy (CFI), Output Low-level policy (NFI)
#http://ipv4:5000/high_level
@api.route('/high_level', methods=['PUT'])
def restInsertConfiguration():
    req = request.json
    #start = datetime.datetime.now()
    data = cleanNullTerms(req)
    print(data)
    xml = dict2xml(data)
    result = generatorv2.gen(xml)
    #end = datetime.datetime.now()
    # time = end-start
    # result["time"] = time.total_seconds()
    # result["optimal"] = optimal.total_seconds()
    # for x,y in result.items():
    #     print(x)
    #     print(y)

    #GET IP ADDRESS OF NSF
    for key,value in result.items():
      client = pymongo.MongoClient("mongodb://127.0.0.1:27017/")
      db = client["nsfDB"]
      col = db["capabilities"]

      query = {"nsf-name":key}
      res = col.find_one(query)
      confd = {'address': res["nsf-access-info"]["ip"],
          'netconf_port': 2022,
          'username': 'admin',
          'password': 'admin'}

      confd_manager = manager.connect(
          host = confd["address"],
          port = confd["netconf_port"],
          username = confd["username"],
          password = confd["password"],
          hostkey_verify = False)
      
      configuration = f"""
<nc:config xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
    {value}
</nc:config>
"""
      confd_configuration = confd_manager.edit_config(target="running",config = configuration)
      confd_manager.close_session()

    return result

def cleanNullTerms(d):
   clean = {}
   for k, v in d.items():
      if isinstance(v, dict):
         nested = cleanNullTerms(v)
         if len(nested.keys()) > 0:
            clean[k] = nested
      elif v is not None:
         clean[k] = v
   return clean

def main(argv):
#  print(sys.argv[1])
  ip = ''
  opts, args = getopt.getopt(argv,"h",["ip=","if="])
  for opt, arg in opts:
    if opt == '-h':
      print("RestAPI.py [--ip <ip-address>|--if <interface-name>]")
      sys.exit()
    elif opt in ("--ip"):
      if re.match("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$",arg):
        ip = arg
      else:
        print(f"{arg} is not a valid IP address")
        sys.exit()
    elif opt in ("--if"):
      try:
        ip = ni.ifaddresses(arg)[ni.AF_INET][0]['addr']
      except ValueError:
        print(f"Invalid interface value. The value must be: {ni.interfaces()}")
        sys.exit()
  if ip == '':
    print(f"""Put the IP address or interface.\nUsage:\nRestAPI.py [--ip <ip-address>|--if <interface-name>]""")
  else:
    api.run(host=ip)

if __name__== '__main__':
  main(sys.argv[1:])
