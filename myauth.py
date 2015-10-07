#!/usr/bin/env python3
from sys import stderr, exit
from threading import Thread
from queue import Empty, Queue
import pyotp
import time
import json
import os

TIME_STEP = 30
CONFIG = "~/.ssh/myauth.json"


def out(*args, **kwargs):
  print(*args, file=stderr, **kwargs)


def die(code, reason=None):
  if reason:
    out(reason)
  exit(code)


def show_qr(issuer, user, secret):
  from subprocess import call
  import shlex
  cmd = "qrencode -t ANSI -m 1 -o -" \
        " 'otpauth://totp/{user}?secret={secret}&issuer={issuer}'"
  cmd = cmd.format(issuer=issuer, user=user, secret=secret)
  out(cmd)  # just in case old qrencode cannot display ANSI
  try:
    call(shlex.split(cmd))
  except FileNotFoundError:
    out("Cannot find qrencode.")


def setup(path):
  from socket import gethostname
  from getpass import getuser
  from base64 import b32encode
  key = os.urandom(17)
  b32key = b32encode(key).decode()
  issuer = gethostname()
  user = getuser()
  show_qr(issuer=issuer, user=user, secret=b32key)
  with open(path, "wt") as fd:
    json.dump(dict(totp_secret=b32key), fd)


def check_totp(secret, cb):
  out("time on server:",
      time.strftime("%Y-%m-%d %H:%M:%S %z"),
      int(time.time()))
  curstamp = int(time.time() / TIME_STEP)
  totp = pyotp.TOTP(bytes(secret, 'ascii'))  # old base64 needs bytes
  for _ in range(2):
    out("pin:", end=' ')
    pin = input()
    for i in range(-1, 2):
      cnt = curstamp + TIME_STEP * i
      expected = totp.generate_otp(cnt)
      if expected == pin:
        cb(('allow', "good otp"))
        return
  else:
    cb(('deny', "wrong otp"))


if __name__ == '__main__':
  path = os.path.expanduser(CONFIG)
  if not os.path.exists(path):
    out("no config found, performing initial setup of %s" % CONFIG)
    setup(path)
  else:
    queue = Queue()
    with open(path, 'rt') as fd:
      cfg = json.load(fd)

    if 'totp_secret' in cfg:
      t = Thread(target=check_totp,
                 kwargs=dict(secret=cfg['totp_secret'],
                 cb=queue.put))
      t.daemon = True
      t.start()

    if 'tokenizer' in cfg:
      from tokenizer import tokenizer
      t = Thread(target=tokenizer,
                 kwargs=dict(cfg=cfg['tokenizer'],
                 cb=queue.put))
      t.daemon = True
      t.start()

    try:
      verdict, reason = queue.get(timeout=15)
      out(verdict, reason)
      if verdict == 'deny':
        die(1)
    except Empty:
      die(2, "timeout")


  orig = os.getenv("SSH_ORIGINAL_COMMAND")
  if orig:
    os.execl("/bin/sh", "/bin/sh", "-c", os.getenv("SSH_ORIGINAL_COMMAND"))
  else:
    # TODO: support executed as as shell
    os.execl(os.getenv("SHELL"), "-" + os.path.basename(os.getenv("SHELL")))
