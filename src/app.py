#!/usr/bin/env python3

import sys


# flask webserver
from flask import Flask, jsonify, make_response
from flask_orator import Orator
from waitress import serve


# db models
from models import *

# global data_container
from libs.data_container import data_container as dc
# dc.config: config dict
# dc.logging: logging object

import toml
import logging

# hardware:
from libs.Solenoid import Solenoid
from libs.Buzzer import Buzzer
from libs.Button import Button


# Read Config settings 
try:
	dc.config = toml.load('config.ini')
except FileNotFoundError:
	sys.exit("Config file 'config.ini' is missing.")



#
# create logger with 'doorlockd'
#
logger = logging.getLogger('doorlockd')
logger.setLevel(dc.config.get('doorlockd',{}).get('log_level', 'NOTSET'))
# create formatter and add it to the handlers
# formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
formatter = logging.Formatter('%(asctime)s - %(module)s - %(levelname)s - %(message)s')

# console output on stderr
ch = logging.StreamHandler()
ch.setLevel(dc.config.get('doorlockd',{}).get('stderr_level', 'INFO'))
ch.setFormatter(formatter)
logger.addHandler(ch)

# file output
if dc.config.get('doorlockd',{}).get('logfile_name'):
	logger.info('logging to filename: {}, level: {}'.format(
		dc.config.get('doorlockd',{}).get('logfile_name'),
		dc.config.get('doorlockd',{}).get('logfile_level', 'INFO') ))

	fh = logging.FileHandler(dc.config.get('doorlockd',{}).get('logfile_name'))
	fh.setLevel(dc.config.get('doorlockd',{}).get('logfile_level', 'INFO'))
	fh.setFormatter(formatter)
	logger.addHandler(fh)

	
dc.logger = logger
dc.logger.info('doorlockd starting up...')


#
# Creating Flask application
#
app = Flask(__name__, static_url_path='', static_folder='static_html')
app.debug = True
app.config['ORATOR_DATABASES'] = dc.config['ORATOR_DATABASES']

#
# Initializing Orator, using flask app.config['ORATOR_DATABASES'] 
#
db = Orator(app)




#
# Main
#
if __name__ == '__main__':
	# enable flask api endpoints:
	import rest_api_models
	rest_api_models.add_to_flask(app)
	
	#
	# setup hardware
	#
	dc.hw = {}

	# 
	# Hardware: Solenoid
	#
	hw_solenoid = Solenoid()
	# hw_solenoid.trigger()
	dc.hw['solenoid'] = hw_solenoid
	# # any_object, json_schema, urlpath=None, app=None, methods=['GET', 'PUT']):
	# api_solenoid = rest_api_models.AnySingleObjectRestApi(hw_solenoid, 'schema/schema.hw.solenoid.json')
	# api_solenoid.flask_add_rules('/api/hw/solenoid', app, methods=['GET', 'PUT'])
	rest_api_models.create_api_for_object(hw_solenoid, 'schema/schema.hw.solenoid.json', '/api/hw/solenoid', app)

	# 
	# Hardware: Buzzer
	#
	dc.hw['buzzer'] = Buzzer()
	rest_api_models.create_api_for_object(dc.hw['buzzer'], 'schema/schema.hw.buzzer.json', '/api/hw/buzzer', app)


	# 
	# Hardware:  Button1, default functionality is intercom: trigger_action = solenoid 
	#
	dc.hw['button1'] = Button('button1', trigger_action='solenoid')
	rest_api_models.create_api_for_object(dc.hw['button1'], 'schema/schema.hw.button.json', '/api/hw/button1', app)

	# 
	# Hardware:  Button2, default functionality is doorbell: trigger_action = buzzer 
	#
	dc.hw['button2'] = Button('button2', trigger_action='buzzer')
	rest_api_models.create_api_for_object(dc.hw['button2'], 'schema/schema.hw.button.json', '/api/hw/button2', app)


	# Flask built in webserver , with DEBUG options
	app.run(host='0.0.0.0', port=8000) ##Replaced with below code to run it using waitress
	
	# Waitress webserver:
	# serve(app, host='0.0.0.0', port=8000) # listen="*:8000"
	# fix waitress logging...
	

