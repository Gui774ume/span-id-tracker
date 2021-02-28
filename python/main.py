from ddtrace import patch_all
from ddtrace import config
config.flask['service_name'] = 'span.tracker.python'
patch_all()

from flask import Flask
import subprocess, fcntl

app = Flask(__name__)

@app.route('/vuln/open')
def vuln_open():
    try:
        f = open("/tmp/secrets", "w+")
        f.close()
    except Exception as e:
        return e
    return 'vuln triggered'

@app.route('/vuln/exec')
def vuln_exec():
    return subprocess.run(["id"], capture_output=True).stdout

@app.route('/vuln/span_altering_attempt')
def vuln_span_altering_attempt():
    try:
        fcntl.ioctl(0, 0xdeadc001, bytearray(int(3).to_bytes(1, "little") + int(123123).to_bytes(8, "little") + int(1234).to_bytes(8, "little") + int(5678).to_bytes(8, "little") + bytes(8) + int(2).to_bytes(8, "little")))
    except OSError:
        pass
    return 'fake span sent !'

@app.route('/hello')
def index():
    return 'hello world'


if __name__ == '__main__':
    app.run()
