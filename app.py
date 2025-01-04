from flask import Flask, request, jsonify
from flask_sock import Sock
from flask_cors import CORS
import subprocess
import json
import psutil
import os
import requests
import time
from tunnel_manager import tunnel_manager

app = Flask(__name__)
CORS(app)
sock = Sock(app)

@app.route('/health')
def health_check():
    return jsonify({'status': 'ok'})

@app.route('/')
def root():
    return jsonify({'message': 'NT8 Webhook Service is running'})

@sock.route('/ws')
def handle_websocket(ws):
    while True:
        try:
            message = ws.receive()
            data = json.loads(message)
            
            if data['type'] == 'start_tunnel':
                port = data['port']
                result = tunnel_manager.start_tunnel(int(port))
                
                if result['status'] == 'success':
                    ws.send(json.dumps({
                        'type': 'tunnel_started',
                        'url': result['url']
                    }))
                else:
                    ws.send(json.dumps({
                        'type': 'error',
                        'message': result['message']
                    }))
                    
            elif data['type'] == 'stop_tunnel':
                port = data['port']
                result = tunnel_manager.stop_tunnel(int(port))
                
                if result['status'] == 'success':
                    ws.send(json.dumps({'type': 'tunnel_stopped'}))
                else:
                    ws.send(json.dumps({
                        'type': 'error',
                        'message': result['message']
                    }))
                    
        except Exception as e:
            ws.send(json.dumps({
                'type': 'error',
                'message': str(e)
            }))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)