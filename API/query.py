from ncclient import manager
from ncclient.operations import RPCError
import xml.dom.minidom
from lxml import etree
import xmltodict, json
import requests
import configparser

config = configparser.ConfigParser()
config.sections()

config.read('../controller.ini')
config.sections()

#print(f"mongodb://{config['DEFAULT']['Controller']}:27017/")


def query_with_file(filename):
    host = "10.0.0.19"

    with manager.connect(host=host, port=2022, username="admin", password="admin", hostkey_verify=False) as m:
        with open(filename, 'r') as f:
            start_rpc = etree.fromstring(f.read())
            try:
                c = m.dispatch(rpc_command=start_rpc)
                data = xmltodict.parse(c.xml)
            except RPCError as e:
                reply = etree.tostring(e._raw, xml_declaration=True)
                data = xmltodict.parse(reply)
    return data

def query_with_string(capability):
    host = "10.0.0.19"
    with manager.connect(host=host, port=2022, username="admin", password="admin", hostkey_verify=False) as m:
        start_rpc = etree.fromstring(capability)
        c = m.dispatch(rpc_command=start_rpc)
        data = xmltodict.parse(c.xml)
    return data

def query(capability):
    url = f"http://{config['DEFAULT']['PrivateController']}:5000/register/nsf"
    data = query_with_string(capability)
    print(data)
    if 'rpc-error' in data:
        print("ERROR")
        return ("NSF Not Found")
    else:
        i=1
        if isinstance(data["rpc-reply"]["nsf"],list):
            for nsf in data["rpc-reply"]["nsf"]:
                print(f"NSF-{i}")
                print(type(nsf))
                print(json.dumps(nsf,indent=4))
                response = requests.put(url, json=nsf)
                print(f"{response.status_code}: {response.reason}, {response.text}")
                i+=1
        else:
            nsf = data["rpc-reply"]["nsf"]
            print(f"NSF-1")
            print(type(nsf))
            print(json.dumps(nsf,indent=4))
            response = requests.put(url, json=nsf)
            print(f"{response.status_code}: {response.reason}, {response.text}")
            i+=1
        return(data["rpc-reply"]["nsf"])

