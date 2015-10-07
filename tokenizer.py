#!/usr/bin/env python

from urllib.request import urlopen
from urllib.parse import urlencode
from threading import Thread
import json
import time


def tokenizer(cfg, cb):
  def create_auth(url='{}v1/authentications.json'):
      data = urlencode({
              'app_id': cfg['id'],
              'app_key': cfg['key'],
              'usr_email': cfg['email']
          }).encode('utf-8')

      url = url.format(cfg['host'])
      response = urlopen(url, data).read().decode('utf-8')
      return json.loads(response)['id']

  def verify_auth(pin, url='{}v1/authentication/{}.json?{}'):
      data = urlencode({'app_id': cfg['id'], 'app_key': cfg['key']})
      url = url.format(cfg['host'], pin, data)
      response = urlopen(url).read().decode('utf-8')
      return json.loads(response)['state']

  pin = create_auth()
  resp = 'timeout'
  for x in range(10):
    resp = verify_auth(pin)
    if resp != 'pending':
      break
    time.sleep(2)
  if resp == 'accepted':
    cb(('allow', "access granted by tokenizer"))
  else:
    cb(('deny', "tokenizer: %s" % resp))
