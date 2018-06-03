#!/usr/bin/env python

import json
import logging
import os
import platform
import re
import subprocess
from contextlib import closing
from threading import Event, Thread

import requests
import tornado.httpserver
import tornado.ioloop
import tornado.web
from monotonic import monotonic
from requests import Request
from respeaker import Microphone

import time

logging.basicConfig(level=logging.DEBUG)

if platform.machine() == 'mips':
    config_file = '/etc/config/alexa.json'
    hint_file = '/root/alexa_hint.mp3'
else:
    config_file = os.path.join(os.path.dirname(__file__), 'alexa.json')
    hint_file = os.path.join(os.path.dirname(__file__), 'alexa_hint.mp3')

product_id = "TopqizhiAlexa"
security_profile_description = "topqizhi product with alexa"
security_profile_id = "amzn1.application.cc23b569c058474e88c5c3179736ef9a"
client_id = "amzn1.application-oa2-client.492422777ce949e0b180d78a3b8f334f"
client_secret = "36dfe47e0ce1db3827cbaf9892ca719c96606b941db096a4f6a766711cf8e409"

refresh_token = None


def get_refresh_token():
    global refresh_token

    if not refresh_token:
        try:
            with open(config_file) as f:
                config = json.load(f)
                print(config)
                refresh_token = config['refreshToken']
                print("load config file ...")
        except Exception as e:
            print(e.message)
            logging.info(e.message)
    #refresh_token = "Atzr|IwEBINI0s8TNFbPytmUlIZ6r1Lp6zyu8nlrOUOcerwFIIkPzFYBO4EI20JpOqQmMALQEvcw7goYVDvRyb7zO1E2cmqxNA_ZfbHkJRNJqnuFnAbOWIayvMt_VIf_vTDo86HIdb3mPTo0FhdoPoCSUThaZqR5Sn2JpE5oazOEjYl0fpI8qIOx56OrdoyjdNKvfAnZrjdOI71xMBujI_zJtQvWsE9oAMqoGPFbqTYcXHkDuCcTfUpSWc0lRITZajh8z9LCQfqiWYbdpT6VWUZKWB3faE5N5KQ7QFGvSTyNrqDeQlx7kZ7gxN83jyD0-xr9NKbi12wDGlA85TSAZnOCLR7wEeTK_UBEsfGf6IrIOtM5s0dQnzDi79EmBuJBGep2MGF2gojQ2SvdGA8GrMLtMt4qnCQEpfz2p3GCLnATNbG_SJQsRYC1TVFujhBP-D5nNNOvnXVauFj1nfmM8HVA7WsUIRvqgZhtcAghgQxZ5KOYSAkXlaoAHWY9rzunSGbLE9nVlMy4GHmbdXaWnm5KnfxR-lNGn"
    return refresh_token


def set_refresh_token(token):
    config = {'refreshToken': token}
    with open(config_file, 'w') as f:
        json.dump(config, f)
        json.dump(config, f)


class MainHandler(tornado.web.RequestHandler):
    @tornado.web.asynchronous
    def get(self):
        if not get_refresh_token():
            sd = json.dumps({
                "alexa:all": {
                    "productID": product_id,
                    "productInstanceAttributes": {
                        "deviceSerialNumber": "123456"
                    }
                }
            })
            url = "https://www.amazon.com/ap/oa"
            path = self.request.protocol + "://" + self.request.host
            callback = path + "/authresponse"
            payload = {"client_id": client_id, "scope": "alexa:all", "scope_data": sd, "response_type": "code",
                       "redirect_uri": callback}
            req = Request('GET', url, params=payload)
            p = req.prepare()
            self.redirect(p.url)
        else:
            self.write('Try asking thing like: "Alexa, what time is it?" or "Alexa, tell me the news".')
            self.finish()


class CodeAuthHandler(tornado.web.RequestHandler):
    @tornado.web.asynchronous
    def get(self):
        global refresh_token

        code = self.get_argument("code")
        path = self.request.protocol + "://" + self.request.host
        callback = path + "/authresponse"
        payload = {"client_id": client_id, "client_secret": client_secret, "code": code,
                   "grant_type": "authorization_code", "redirect_uri": callback}
        url = "https://api.amazon.com/auth/o2/token"
        r = requests.post(url, data=payload)
        resp = r.json()
        refresh_token = resp['refresh_token']
        set_refresh_token(refresh_token)

        self.write('Done! Try asking thing like: "What time is it?" or "Tell me the news".')
        self.finish()


def generate(audio, boundary):
    """
    Generate a iterator for chunked transfer-encoding request of Alexa Voice Service
    Args:
        audio: raw 16 bit LSB audio data
        boundary: boundary of multipart content

    Returns:

    """
    logging.debug('Start sending speech to Alexa Voice Service')
    chunk = '--%s\r\n' % boundary

    chunk += (
        'Content-Disposition: form-data; name="request"\r\n'
        'Content-Type: application/json; charset=UTF-8\r\n\r\n'
    )

    d = {
        "messageHeader": {
            "deviceContext": [{
                "name": "playbackState",
                "namespace": "AudioPlayer",
                "payload": {
                    "streamId": "",
                    "offsetInMilliseconds": "0",
                    "playerActivity": "IDLE"
                }
            }]
        },
        "messageBody": {
            "profile": "alexa-close-talk",
            "locale": "en-us",
            "format": "audio/L16; rate=16000; channels=1"
        }
    }

    yield chunk + json.dumps(d) + '\r\n'

    chunk = '--%s\r\n' % boundary
    chunk += (
        'Content-Disposition: form-data; name="audio"\r\n'
        'Content-Type: audio/L16; rate=16000; channels=1\r\n\r\n'
    )

    yield chunk

    for a in audio:
        yield a

    yield '--%s--\r\n' % boundary
    logging.debug('Finished sending speech to Alexa Voice Service')

class Alexa:
    """
    Provide Alexa Voice Service based on API v1
    """

    def __init__(self):
        self.access_token = None
        self.expire_time = None
        self.session = requests.Session()

    def get_token(self):
        if self.expire_time is None or monotonic() > self.expire_time:
            # get an access token using OAuth
            credential_url = "https://api.amazon.com/auth/o2/token"
            data = {
                "client_id": client_id,
                "client_secret": client_secret,
                "refresh_token": get_refresh_token(),
                "grant_type": "refresh_token",
            }
            start_time = monotonic()
            r = self.session.post(credential_url, data=data)

            if r.status_code != 200:
                raise Exception("Failed to get token. HTTP status code {}".format(r.status_code))

            credentials = r.json()
            self.access_token = credentials["access_token"]
            self.expire_time = start_time + float(credentials["expires_in"])

        return self.access_token

    def recognize(self, audio):
        url = 'https://access-alexa-na.amazon.com/v1/avs/speechrecognizer/recognize'
        #url = 'https://avs-alexa-na.amazon.com/v20160207/events'
        boundary = 'this-is-a-boundary'
        save_to = '/tmp/test.mp3'
#        save_to = "{}/{}.mp3".format(self.temp_dir, uuid.uuid4())

        headers = {
            'Authorization': 'Bearer %s' % self.get_token(),
            'Content-Type': 'multipart/form-data; boundary=%s' % boundary,
            'Transfer-Encoding': 'chunked',
        }
        data = generate(audio, boundary)
        with closing(self.session.post(url, headers=headers, data=data, timeout=60, stream=True)) as r:
            with open(save_to,'wb') as f:
                if r.status_code == 200:
                    for v in r.headers['content-type'].split(";"):
                        if re.match('.*boundary.*', v):
                            boundary = v.split("=")[1]
                    response_data = r.content.split(boundary)
                    audio = None
                    for d in response_data:
                        if (len(d) >= 1024):
                            audio = d.split('\r\n\r\n')[1].rstrip('--')
                    if audio is None:
                        raise RuntimeError("Failed to save response audio")
                    f.write(audio)
                #elif r.status_code == 403:
                #    print "the token expired, get the access token again...\n"
                    #get_refresh_token() 


            '''
            if r.status_code != 200:
                raise Exception("Failed to recognize. HTTP status code {}".format(r.status_code))

            for v in r.headers['content-type'].split(";"):
                if re.match('.*boundary.*', v):
                    boundary = v.split("=")[1]

            if not boundary:
                logging.warn('No boundary is found in headers')
                return

            content = r.iter_content(chunk_size=4096)
            prefix = next(content)
            position = prefix.find(boundary, len(boundary))  # skip first boundary
            if position < 0:
                logging.warn('No boundary is found. Invalid format')
                return

            start = position + len(boundary) + 2  # boundary + cr + lf
            speech = prefix[start:]

            if platform.machine() == 'mips':
                command = 'madplay -o wave:- - | aplay -M'
            else:
                command = 'ffplay -autoexit -nodisp -'

            p = subprocess.Popen(command, stdin=subprocess.PIPE, shell=True)
            p.stdin.write(speech)
            for speech in content:
                p.stdin.write(speech)

            p.stdin.close()
            p.wait()

            '''

            if platform.machine() == 'mips':
                #command = 'madplay -S /tmp/test.mp3'
                if os.access("/tmp/test.mp3", os.F_OK):
                    command = 'spi_play /tmp/test.mp3'
                    p = subprocess.Popen(command, shell=True).wait()
            else:
                command = 'ffplay -autoexit -nodisp -'
                p = subprocess.Popen(command, shell=True).wait()

            return save_to

def login():
    logging.info("Go to http://192.168.100.1:3000 to sign up or login Alexa Voice Service")
    application = tornado.web.Application([(r"/", MainHandler),
                                           (r"/authresponse", CodeAuthHandler),
                                           ])
    http_server = tornado.httpserver.HTTPServer(application)
    http_server.listen(3000)
    tornado.ioloop.IOLoop.instance().start()
    tornado.ioloop.IOLoop.instance().close()

def get_token_loop():
    while not get_refresh_token():
        time.sleep(5)
        print "get refresh token...\n"

def main():
    import signal

    thread = None
    #if not get_refresh_token():
    #    thread = Thread(target=login)
    #    thread.daemon = True
    #    thread.start()

    if not get_refresh_token():
        thread = Thread(target=get_token_loop)
        thread.daemon = True
        thread.start()

    quit_event = Event()

    def handler(signum, frame):
        quit_event.set()
        if thread:
            tornado.ioloop.IOLoop.instance().stop()

    signal.signal(signal.SIGINT, handler)

    get_refresh_token()

    #mosq_command='/usr/bin/mosquitto_sub -h 120.27.138.117 -t umomoSofa -v &'    
    mosq_command='/usr/bin/mosquitto_sub'    
    subprocess.Popen(mosq_command, shell=True)        
    mic_command='/usr/bin/mic_wake'    
    subprocess.Popen(mic_command, shell=True)        

    mic = Microphone(quit_event=quit_event)
    alexa = Alexa()
    print("========================alexa start========================")
    while not quit_event.is_set():
        with open('/etc/config/mic_wake') as f:
            contents = f.read()
        #if mic.wakeup(keyword='alexa'):
        if "1" in contents:
            logging.debug('wakeup')
            if not get_refresh_token():
                if platform.machine() == 'mips':
                    command = 'madplay -o wave:- {} | aplay -M'.format(hint_file)
                else:
                    command = 'ffplay -autoexit -nodisp {}'.format(hint_file)

                subprocess.Popen(command, shell=True).wait()
                continue

            data = mic.listen()
            print("========================alexa listen========================")
            try:
                alexa.recognize(data)
            except Exception as e:
                logging.warn(e.message)

    mic.close()
    logging.debug('Mission completed')


if __name__ == '__main__':
    main()

