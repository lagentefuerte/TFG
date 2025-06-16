from flask import Flask, make_response, send_file, request, Response

app = Flask(__name__)

@app.route("/session", methods=["GET"])
def send_hash():
    with open("mi_hash.txt", "r") as f:
        hash = f.read().strip()
    cookie_value = request.cookies.get('cookie')
    if cookie_value == hash.lower():
        return Response(status=200)
    else:
        return Response(status=404)

@app.route("/image.png", methods=["GET"])
def send_dll():
    with open("image.png", "rb") as f:
        dll = f.read()
    response = make_response(dll)
    response.headers["Server"] = "nginx/1.23.4"
    response.headers["Content-Type"] = "application/octet-stream"
    return response

@app.route("/favicon.ico", methods=["GET"])
def send_ico():
   with open("favicon.ico", "rb") as f:
       dll = f.read()
   response = make_response(dll)
   response.headers["Server"] = "nginx/1.23.4"
   response.headers["Content-Type"] = "application/octet-stream"
   return response

@app.route("/index.html", methods=["GET"])
def send_payload():
    with open("index.html", "rb") as f:
        payload = f.read()
    rc4_key = "supersecreta"
    response = make_response(payload)
    response.headers["Server"] = "nginx/" + rc4_key
    response.headers["Content-Type"] = "application/octet-stream"
    return response

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
