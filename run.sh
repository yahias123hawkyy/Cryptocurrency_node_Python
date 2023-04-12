#!/bin/bash
#TODO check whether requirements.txt is complete
pip install -r requirements.txt

python3 create_db.py
python3 main.py 127.0.0.1 18018
