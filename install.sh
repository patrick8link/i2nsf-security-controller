#!/bin/bash
sudo apt-get install python3-dev libmysqlclient-dev python3-pip
curl -sL https://deb.nodesource.com/setup_14.x | sudo bash -
python3 -m pip instal pyopenssl
python3 -m pip install pymongo regex flask flask_cors dict2xml mysqlclient zss pyangbind ncclient xmltodict pulp
