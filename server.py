from flask import Flask, jsonify

app = Flask(__name__)

app.route('/')
def home():
    return jsonify({'name': 'py pos implementation of https://github.com/mycoralhealth/blockchain-tutorial'
                    "version": "0.1.0"})