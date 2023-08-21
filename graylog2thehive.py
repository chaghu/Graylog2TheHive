from __future__ import print_function
from __future__ import unicode_literals
import sys
import requests
import json
import time
import uuid
import logging
import re
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact, CustomFieldHelper
from flask import Flask, Response, render_template, request, flash, redirect, url_for

app = Flask(__name__)

def flatten_dict(d):
    def items():
        for key, value in d.items():
            if isinstance(value, dict):
               for subkey, subvalue in flatten_dict(value).items():
                    yield subkey, subvalue
            else:
                yield key, value

    return dict(items())

# Configure TheHiveAPI URL and API code here
# Exmaple : api = TheHiveApi('http://127.0.0.1:9000', 'HYEOKSYEHZFSQHZYTSRF')
api = TheHiveApi('http://167.99.75.127:9000', 'l9fVhnh/971k8vjSCPDKz8zZg7yoxofb')

# Configure Graylog URL here
# Exmaple : graylog_url = 'http://10.10.10.10:9000'
graylog_url = 'https://chai.salaam.co.ke:2087'

# Webhook to process Graylog HTTP Notification
@app.route('/webhook', methods=['POST'])
def webhook():

    # Get request JSON contents
    content = request.get_json()
    event = content['event']

    # Configure artifacts
    artifacts = []

    # Configure Alert tags
    tags = ['Graylog']

    # Configure Alert title
    title = event['message']


    # Configure Alert severity
    severity = event['priority']

    # Configure Alert description
    description = "**Graylog event definition:** "+content['event_definition_title']
    if content['backlog']:
        description = description+'\n\n**Matching messages:**\n\n'
        for message in content['backlog']:
            description = description+"\n\n---\n\n**Graylog URL:** "+graylog_url+"/messages/"+message['index']+"/"+message['id']+"\n\n"
            description = description+'\n\n**Raw Message:** \n\n```\n'+json.dumps(message)+'\n```\n---\n'


        for field in ["threat_name","threat_tactic","threat_technique","threat_id"]:
            try:
                if message["fields"][field] not in tags:
                    tags.append(message["fields"][field])
            except:
                pass

        message_flattened=flatten_dict(message)
        for key in message_flattened.keys():
            if key != "message" and key != "source":
                description=description+"\n**"+key+":** "+json.dumps(message_flattened[key], ensure_ascii=False)+"\n"

            # Use any IPs, hashes, URLs, filenames, etc here in place of src_ip and dst_ip to include them as artifacts/observables in your alert
            if key == "src_ip" or key == "dst_ip":
                artifacts.append(AlertArtifact(dataType='ip', tags=[key], data=message_flattened[key]))
            elif key == "rhost":
                artifacts.append(AlertArtifact(dataType='ip', tlp=3, tags=[key], data=message_flattened[key]))
            elif key == "md5" or key == "sha256" or key == "imphash":
                artifacts.append(AlertArtifact(dataType='hash', tags=[key], data=message_flattened[key]))
            elif key == "url":
                artifacts.append(AlertArtifact(dataType='url', tags=[key], data=message_flattened[key]))
            elif key == "useragent":
                artifacts.append(AlertArtifact(dataType='user-agent', tags=[key], data=message_flattened[key]))
            elif key == "Image" or key == "ParentImage":
                artifacts.append(AlertArtifact(dataType='filename', tags=[key], data=message_flattened[key]))
            elif key == "NewProcessName" or key == "ParentProcessName":
                artifacts.append(AlertArtifact(dataType='filename', tags=[key], data=message_flattened[key]))
            elif key == "filename":
                artifacts.append(AlertArtifact(dataType='filename', tags=[key], data=message_flattened[key]))
            elif key == "service_name":
                artifacts.append(AlertArtifact(dataType='other', tags=[key], data=message_flattened[key]))
            elif key == "dst_hostname":
                artifacts.append(AlertArtifact(dataType='fqdn', tags=[key], data=message_flattened[key]))
            elif key == "src_hostname" or key == "hostname":
                artifacts.append(AlertArtifact(dataType='other', tlp=3, tags=[key], data=message_flattened[key]))
            elif key == "Client IP":
                artifacts.append(AlertArtifact(dataType='ip', tlp=3, tags=[key], data=message_flattened[key]))

    # Prepare the Alert
    sourceRef = str(uuid.uuid4())[0:6]
    alert = Alert(title=title,
                  tlp=2,
                  tags=tags,
                  description=description,
                  severity=severity,
                  artifacts=artifacts,
                  type='external',
                  source='Graylog',
                  sourceRef=sourceRef)

    # Create the Alert
    print('Creating alert for: '+title)
    response = api.create_alert(alert)
    if response.status_code == 201:
        print('Alert created successfully for: '+title)
    else:
        print('Error while creating alert for: '+title)
        sys.exit(0)
    return content['event_definition_title']
