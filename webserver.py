import logging
import os
from threading import Thread


from flask import Flask, jsonify


app = Flask(__name__)


@app.route('/')
def home():
    return 'discord bot ok', 200


@app.route('/health')
def health():
    return jsonify(status="ok", service="discord-bot"), 200


def run():
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port)


def keep_alive():
    t = Thread(target=run, daemon=True)
    t.start()
