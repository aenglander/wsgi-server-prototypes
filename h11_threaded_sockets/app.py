import logging

from flask import Flask, request

from wsgi_server import WebServer

app = Flask("Example App")


@app.get("/")
@app.get("/hello/<name>")
def get_hello_name(name="World"):
    return "<html>\n" \
           f"    <head><title>Hello, {name}!</title></head>\n" \
           f"    <body><p>Hello, {name}!</p></body>\n" \
           "</html>\n"


@app.post("/")
def hello_name():
    name = request.form.get("name")
    return get_hello_name(name)


if __name__ == '__main__':
    server = WebServer(log_level=logging.DEBUG)
    server.listen("0.0.0.0", 8080, app)
