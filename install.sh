#!/bin/bash
sudo apt-get update
sudo apt-get install python3-dev libmysqlclient-dev -y
sudo python3 get-pip.py

curl -sL https://deb.nodesource.com/setup_14.x | sudo bash -

python3 -m pip install pymongo regex flask flask_cors dict2xml mysqlclient zss pyangbind ncclient xmltodict pulp
pip install pyopenssl

source $HOME/.bashrc

cd API
sh generate_bindings.sh
