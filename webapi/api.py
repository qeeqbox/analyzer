from threading import Thread
from flask import Flask, jsonify, make_response, request
from werkzeug.exceptions import HTTPException
from ..connections.mongodbconn import get_it_fs
from ..mics.certmaker import create_dummy_certificate
from ..queue.mongoqueue import qbjobqueue
from os import mkdir, path

app = Flask(__name__)
queue = qbjobqueue("jobsqueue", False)

@app.route("/qeeqbox/analyzer/tasks/get/<string:_type>/<string:task_id>", methods=["GET"])
def get_task(_type,task_id):
    x = None
    if not task_id:
        return jsonify(uuid="Please provide uuid")
    if _type == "json":
        x = get_it_fs("dumps", {"uuid": task_id,"type":"JSON"})
        response = make_response(x)
        response.mimetype = "application/json"
        return response
    elif _type == "html":
        x = get_it_fs("dumps", {"uuid": task_id,"type":"HTML"})
        response = make_response(x)
        response.mimetype = "text/html"
        return response
    else:
        return jsonify(uuid="Please provide type (json or html)")
    return jsonify(error="Task..")


@app.route("/qeeqbox/analyzer/tasks/create", methods=["POST"])
def create_task():
    if not request.json:
        return jsonify(json="Please provide json")
    json_content = request.get_json(silent=True)
    if len(json_content) > 0:
        q_return = queue.insert(json_content)
        return jsonify(task=q_return)
    else:
        return jsonify(task="Please provide json")


def error_handler(error):
    return jsonify(error="Something wrong")


for cls in HTTPException.__subclasses__():
    app.register_error_handler(cls, error_handler)

#do not use in production
def runwebapi():
    certsdir = path.abspath(path.join(path.dirname( __file__ ),'certs'))
    if not certsdir.endswith(path.sep): certsdir = certsdir+path.sep
    if not path.isdir(certsdir): mkdir(certsdir)
    if create_dummy_certificate('cert.pem', 'key.pem',certsdir,False):
        Thread(target=app.run,kwargs={"host": "127.0.0.1", "port": 8001, "use_reloader": False,"ssl_context":(certsdir+'cert.pem', certsdir+'key.pem')},).start()

# curl localhost:8001/qeeqbox/analyzer/tasks/create -d '{"buffer": "goo9le.com","full":"True","print":"True","json":"True", "open":"True"}' -H 'Content-Type: application/json
# curl localhost:8001/qeeqbox/analyzer/tasks/get/809cad06-917f-43e1-b02c-8aab68e17110
