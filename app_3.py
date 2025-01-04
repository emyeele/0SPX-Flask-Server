from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, session
from functools import wraps
import os
import json
import requests
from datetime import datetime
import time
import pytz
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from collections import defaultdict
import threading
import logging

# Suppress HTTP access logs
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Secure random key for session management

# -----------------------------------------------------------------------------------
# Global Configuration and Data Structures
# -----------------------------------------------------------------------------------
config_path = 'config.json'
config = {"strategies": {}}

# Load configuration if it exists
if os.path.exists(config_path):
    with open(config_path, 'r') as f:
        config = json.load(f)

# Initialize Flask-Limiter to apply rate limits
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]  # Default rate limit for the app
)

# Dictionary to store pending alerts
# Key: (ticker, numeric_id)
# Value: list of alerts with that key
pending_alerts = defaultdict(list)

# Set to keep track of processed and discarded alerts
processed_trade_ids = set()
discarded_numeric_ids = set()

# Lock for thread-safe operations
lock = threading.Lock()

# Configurable delay in seconds before processing an alert
DELAY_SECONDS = 2

# -----------------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------------
def save_config():
    """Save the global config dictionary to disk."""
    with open(config_path, 'w') as f:
        json.dump(config, f, indent=4)

def extract_numeric_id(trade_id):
    """
    Extract the numeric portion from a trade_id.
    Examples:
      "Open_Short_ID_627"  -> 627
      "Close_Short_ID_1503" -> 1503
    """
    try:
        parts = trade_id.split("_")
        return int(parts[-1])
    except (ValueError, IndexError):
        return 0

def truncate_time_to_minute(time_str):
    """
    Truncate the ISO 8601 timestamp to minute precision.
    """
    try:
        dt = datetime.fromisoformat(time_str.replace("Z", "")).replace(tzinfo=pytz.utc)
        dt = dt.replace(second=0, microsecond=0)
        return dt.isoformat().replace("+00:00", "Z")
    except ValueError:
        return time_str

def background_processor():
    """
    Background thread to process pending alerts.
    """
    while True:
        current_time = time.time()
        to_process = []
        with lock:
            keys_to_remove = []
            for key, alerts in list(pending_alerts.items()):
                ticker, numeric_id = key

                # Skip duplicate alerts
                if not alerts:
                    keys_to_remove.append(key)
                    continue

                if (ticker, numeric_id) in discarded_numeric_ids:
                    print(f"Skipping previously discarded alert for (ticker, numeric_id)=({ticker}, {numeric_id})")
                    keys_to_remove.append(key)
                    continue

                alerts.sort(key=lambda x: x['arrival_time'])
                first_alert_time = alerts[0]['arrival_time']

                # Process if past delay
                if current_time - first_alert_time >= DELAY_SECONDS:
                    alert_entry = alerts.pop(0)
                    alert = alert_entry['data']
                    trade_id = alert['trade_id']

                    # Deduplicate
                    if trade_id in processed_trade_ids:
                        print(f"Skipping already processed alert: {trade_id}")
                        continue

                    to_process.append(alert)
                    processed_trade_ids.add(trade_id)
                    discarded_numeric_ids.add((ticker, numeric_id))

                    if not alerts:
                        keys_to_remove.append(key)

            for key in keys_to_remove:
                del pending_alerts[key]

        for alert in to_process:
            print("\n--- BEGIN PROCESSING ALERT ---")
            process_single_alert(alert)

        time.sleep(1)

def process_single_alert(alert):
    """
    Process and forward the alert to NinjaTrader.
    """
    ticker = alert["ticker"]
    action = alert["action"]
    current_position = alert["current_position"]
    qty = int(alert.get("qty", 1))
    price = float(alert.get("price", 0.0))
    trade_id = alert["trade_id"]
    time_str = alert["time"]

    print(f"Processing alert: ticker={ticker}, action={action}, current_position={current_position}, qty={qty}, price={price}, trade_id={trade_id}, time={time_str}")
    truncated_time_str = truncate_time_to_minute(time_str)

    try:
        utc = pytz.utc
        eastern = pytz.timezone('US/Eastern')
        utc_time = datetime.fromisoformat(truncated_time_str.replace("Z", "")).replace(tzinfo=utc)
        est_time = utc_time.astimezone(eastern).strftime('%m/%d/%Y %I:%M:%S %p')
    except ValueError as e:
        print(f"Error converting time for alert with trade_id={trade_id}: {e}")
        return

    if action == "buy":
        mapped_action = "open" if current_position != "short" else "close"
        direction = "long" if mapped_action == "open" else "short"
    elif action == "sell":
        mapped_action = "open" if current_position != "long" else "close"
        direction = "short" if mapped_action == "open" else "long"
    else:
        print(f"Unknown action type for alert with trade_id={trade_id}. Skipping.")
        return

    payload = {
        "ticker": ticker,
        "action": mapped_action,
        "direction": direction,
        "qty": qty,
        "price": price,
        "time": est_time
    }

    print(json.dumps(payload, indent=4))
    sent_ports = set()  # Track unique ports to prevent duplicate logs
    for strategy_name, strategy_data in config['strategies'].items():
        if ticker in strategy_data['tickers']:
            ports = strategy_data['tickers'][ticker]['ports']
            for port in set(ports):  # Use a set to eliminate duplicates
                if port not in sent_ports:
                    send_data_to_nt8(port, payload)
                    sent_ports.add(port)  # Mark port as processed

    print("--- END ALERT PROCESSING ---")

def send_data_to_nt8(port, payload):
    """
    Send data to NinjaTrader listener.
    """
    headers = {'Content-Type': 'application/json'}
    try:
        response = requests.post(f'http://localhost:{port}/receive', json=payload, headers=headers, timeout=5)
        response.raise_for_status()
        print(f"Data sent to port {port}: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Failed to send data to port {port}: {e}")

# -----------------------------------------------------------------------------------
# Webhook Route
# -----------------------------------------------------------------------------------
@app.route('/webhook', methods=['POST'])
def webhook():
    data = request.json
    if not data:
        return jsonify({'status': 'error', 'message': 'No data provided'}), 400

    ticker = data["ticker"]
    trade_id = data["trade_id"]
    numeric_id = extract_numeric_id(trade_id)
    current_time = time.time()

    with lock:
        print("\n--- RECEIVED ALERT ---")
        # Log checks for duplicate detection
        print(f"Received alert: ticker={ticker}, trade_id={trade_id}, numeric_id={numeric_id}")

        # Prevent duplicate enqueuing
        if (ticker, numeric_id) in discarded_numeric_ids:
            print(f"Duplicate alert (discarded): {trade_id} with (ticker, numeric_id)=({ticker}, {numeric_id})")
            return jsonify({'status': 'skipped', 'message': 'Duplicate alert'}), 200

        if trade_id in processed_trade_ids:
            print(f"Duplicate alert (processed): {trade_id}")
            return jsonify({'status': 'skipped', 'message': 'Duplicate alert'}), 200

        # Check for alerts in the queue within the delay window
        for alert_entry in pending_alerts.get((ticker, numeric_id), []):
            if current_time - alert_entry['arrival_time'] < DELAY_SECONDS:
                print(f"Discarding both alerts within delay window: {trade_id}")
                discarded_numeric_ids.add((ticker, numeric_id))
                # Remove existing alert in queue for this (ticker, numeric_id)
                pending_alerts[(ticker, numeric_id)] = []
                return jsonify({'status': 'skipped', 'message': 'Both alerts discarded within delay window'}), 200

        # Enqueue the alert
        alert_entry = {'data': data, 'arrival_time': current_time}
        pending_alerts[(ticker, numeric_id)].append(alert_entry)
        print("\n--- Enqueued Alert ---")
        print(json.dumps(data, indent=4))

    return jsonify({'status': 'success', 'message': 'Alert queued'}), 200

# -----------------------------------------------------------------------------------
# Debugging Route
# -----------------------------------------------------------------------------------
@app.route('/debug_routes', methods=['GET'])
def debug_routes():
    """
    Debug route to list all available routes in the Flask app.
    """
    routes = []
    for rule in app.url_map.iter_rules():
        methods = ','.join(rule.methods)
        routes.append(f"{rule.endpoint}: {rule.rule} [{methods}]")
    return jsonify({'routes': routes})

# -----------------------------------------------------------------------------------
# Management Routes
# -----------------------------------------------------------------------------------
@app.route('/add_strategy', methods=['POST'])
def add_strategy():
    strategy_name = request.form.get('strategy_name')
    if not strategy_name:
        flash("Strategy name is required", "danger")
        return redirect(url_for('index'))

    if strategy_name not in config['strategies']:
        config['strategies'][strategy_name] = {"accounts": {}, "tickers": {}}
        save_config()
        flash(f"Strategy '{strategy_name}' added successfully", "success")
    else:
        flash(f"Strategy '{strategy_name}' already exists", "warning")

    return redirect(url_for('index'))

@app.route('/delete_strategy/<strategy_name>', methods=['POST'])
def delete_strategy(strategy_name):
    if strategy_name in config['strategies']:
        del config['strategies'][strategy_name]
        save_config()
        flash(f"Strategy '{strategy_name}' deleted successfully", "success")
    else:
        flash(f"Strategy '{strategy_name}' not found", "danger")

    return redirect(url_for('index'))

@app.route('/add_ticker/<strategy_name>', methods=['POST'])
def add_ticker(strategy_name):
    ticker_name = request.form.get('ticker_name')
    if not ticker_name:
        flash("Ticker name is required", "danger")
        return redirect(url_for('index'))

    ensure_strategy_data_integrity()
    if strategy_name in config['strategies']:
        if ticker_name not in config['strategies'][strategy_name]['tickers']:
            config['strategies'][strategy_name]['tickers'][ticker_name] = {"ports": []}
            save_config()
            flash(f"Ticker '{ticker_name}' added to strategy '{strategy_name}'", "success")
        else:
            flash(f"Ticker '{ticker_name}' already exists", "warning")
    else:
        flash(f"Strategy '{strategy_name}' not found", "danger")

    return redirect(url_for('index'))

@app.route('/delete_ticker/<strategy_name>/<ticker_name>', methods=['POST'])
def delete_ticker(strategy_name, ticker_name):
    if strategy_name in config['strategies'] and ticker_name in config['strategies'][strategy_name]['tickers']:
        del config['strategies'][strategy_name]['tickers'][ticker_name]
        save_config()
        flash(f"Ticker '{ticker_name}' deleted from strategy '{strategy_name}'", "success")
    else:
        flash(f"Ticker or Strategy not found", "danger")

    return redirect(url_for('index'))

@app.route('/add_port/<strategy_name>/<ticker_name>', methods=['POST'])
def add_port(strategy_name, ticker_name):
    port = request.form.get('port')
    if not port:
        flash("Port is required", "danger")
        return redirect(url_for('index'))

    ensure_strategy_data_integrity()
    if strategy_name in config['strategies'] and ticker_name in config['strategies'][strategy_name]['tickers']:
        if 'ports' not in config['strategies'][strategy_name]['tickers'][ticker_name]:
            config['strategies'][strategy_name]['tickers'][ticker_name]['ports'] = []
        if port not in config['strategies'][strategy_name]['tickers'][ticker_name]['ports']:
            config['strategies'][strategy_name]['tickers'][ticker_name]['ports'].append(port)
            save_config()
            flash(f"Port '{port}' added to ticker '{ticker_name}' in strategy '{strategy_name}'", "success")
        else:
            flash(f"Port '{port}' already exists", "warning")
    else:
        flash("Strategy or Ticker not found", "danger")

    return redirect(url_for('index'))

@app.route('/delete_port/<strategy_name>/<ticker_name>/<port>', methods=['POST'])
def delete_port(strategy_name, ticker_name, port):
    if strategy_name in config['strategies'] and ticker_name in config['strategies'][strategy_name]['tickers']:
        if port in config['strategies'][strategy_name]['tickers'][ticker_name]['ports']:
            config['strategies'][strategy_name]['tickers'][ticker_name]['ports'].remove(port)
            save_config()
            flash(f"Port '{port}' deleted from ticker '{ticker_name}' in strategy '{strategy_name}'", "success")
        else:
            flash(f"Port '{port}' not found", "danger")
    else:
        flash("Strategy or Ticker not found", "danger")

    return redirect(url_for('index'))

# -----------------------------------------------------------------------------------
# Default Route
# -----------------------------------------------------------------------------------
@app.route('/', methods=['GET'])
def index():
    """
    Render the management UI for strategies and tickers.
    """
    ensure_strategy_data_integrity()
    return render_template('index.html', config=config)

def ensure_strategy_data_integrity():
    """
    Ensure all strategies have the necessary attributes initialized.
    """
    for strategy_name, strategy_data in config["strategies"].items():
        if "accounts" not in strategy_data:
            strategy_data["accounts"] = {}
        if "tickers" not in strategy_data:
            strategy_data["tickers"] = {}

# -----------------------------------------------------------------------------------
# Start Background Thread
# -----------------------------------------------------------------------------------
threading.Thread(target=background_processor, daemon=True).start()

if __name__ == '__main__':
    app.run(port=5000, debug=True)
