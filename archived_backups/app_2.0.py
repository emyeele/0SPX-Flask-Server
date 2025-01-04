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
# Key: (ticker, truncated_time_str)
# Value: list of alerts with that key
pending_alerts = defaultdict(list)

# Set to keep track of trade_ids that have been processed or discarded
processed_trade_ids = set()

# Set to keep track of (ticker, truncated_time_str, numeric_id) that have been discarded
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

def ensure_strategy_data_integrity():
    """Ensure all strategies have the necessary attributes initialized."""
    for strategy_name, strategy_data in config["strategies"].items():
        if "accounts" not in strategy_data:
            strategy_data["accounts"] = {}
        if "tickers" not in strategy_data:
            strategy_data["tickers"] = {}

def send_data_to_nt8(port, payload):
    """Send data to the NinjaTrader HTTP listener with retry logic."""
    max_retries = 3
    headers = {'Content-Type': 'application/json'}
    for attempt in range(max_retries):
        try:
            print(f"Attempting to send data to port {port}...")
            response = requests.post(f'http://localhost:{port}/receive', json=payload, headers=headers, timeout=5)
            response.raise_for_status()
            print(f"Data successfully sent to port {port}, Response: {response.status_code}")
            break
        except requests.exceptions.RequestException as e:
            print(f"Attempt {attempt + 1} failed: {e}")
            time.sleep(2)

def extract_numeric_id(trade_id):
    """
    Extract the numeric portion from a trade_id.
    Examples:
      "Open_Short_ID_627"  -> 627
      "Close_Short_ID_1503" -> 1503
    """
    try:
        parts = trade_id.split("_")
        numeric_str = parts[-1]
        return int(numeric_str)
    except (ValueError, IndexError):
        return 0  # fallback if parse fails

# **Replace truncate_time_to_seconds with truncate_time_to_minute**
def truncate_time_to_minute(time_str):
    """
    Truncate the ISO 8601 timestamp to minute precision, removing seconds and milliseconds.
    Example:
        "2025-01-03T00:36:01Z" -> "2025-01-03T00:36Z"
    """
    try:
        dt = datetime.fromisoformat(time_str.replace("Z", "")).replace(tzinfo=pytz.utc)
        dt = dt.replace(second=0, microsecond=0)
        return dt.isoformat().replace("+00:00", "Z")
    except ValueError:
        # If parsing fails, return the original string (you might want to handle this differently)
        return time_str

def background_processor():
    """
    Background thread that processes pending alerts after a delay.
    Discards conflicting alerts and processes non-conflicting ones in ascending order of numeric_id.
    """
    while True:
        current_time = time.time()
        to_process = []
        with lock:
            keys_to_remove = []
            for key, alerts in list(pending_alerts.items()):
                ticker, truncated_time_str = key  # Already minute-truncated
                if not alerts:
                    # If no alerts remain, mark the key for removal
                    keys_to_remove.append(key)
                    continue

                # Sort alerts by numeric_id in ascending order
                alerts.sort(key=lambda x: extract_numeric_id(x['data']['trade_id']))

                # Check if the first alert has been pending for at least DELAY_SECONDS
                first_alert_time = alerts[0]['arrival_time']
                if current_time - first_alert_time >= DELAY_SECONDS:
                    # Detect conflicts: same numeric_id appearing more than once
                    numeric_id_counts = defaultdict(int)
                    for alert_entry in alerts:
                        numeric_id = extract_numeric_id(alert_entry['data']['trade_id'])
                        numeric_id_counts[numeric_id] += 1

                    # Identify conflicting numeric_ids
                    conflicting_numeric_ids = {nid for nid, count in numeric_id_counts.items() if count > 1}

                    # Discard alerts with conflicting numeric_ids
                    if conflicting_numeric_ids:
                        for alert_entry in alerts:
                            trade_id = alert_entry['data']['trade_id']
                            numeric_id = extract_numeric_id(trade_id)
                            if numeric_id in conflicting_numeric_ids:
                                processed_trade_ids.add(trade_id)
                                discarded_numeric_ids.add((ticker, truncated_time_str, numeric_id))
                                print(f"Discarding alert with trade_id={trade_id} due to conflicting numeric_id={numeric_id}.")
                        # Remove conflicting alerts from the list
                        alerts = [alert for alert in alerts if extract_numeric_id(alert['data']['trade_id']) not in conflicting_numeric_ids]
                        pending_alerts[key] = alerts
                        if not alerts:
                            keys_to_remove.append(key)

                    # After discarding conflicts, check if any alerts remain to process
                    if pending_alerts[key]:
                        # Process the first alert (lowest numeric_id)
                        alert_entry = pending_alerts[key].pop(0)
                        alert = alert_entry['data']
                        to_process.append(alert)
                        trade_id = alert['trade_id']
                        numeric_id = extract_numeric_id(trade_id)
                        processed_trade_ids.add(trade_id)
                        discarded_numeric_ids.add((ticker, truncated_time_str, numeric_id))
                        print(f"Processing alert with trade_id={trade_id}.")
                        # If no more alerts remain for this key, mark it for removal
                        if not pending_alerts[key]:
                            keys_to_remove.append(key)

            # Remove keys with no remaining alerts
            for key in keys_to_remove:
                del pending_alerts[key]

        # Process alerts outside the lock to avoid blocking
        for alert in to_process:
            process_single_alert(alert)

        # Sleep briefly before next check
        time.sleep(1)

def process_single_alert(alert):
    """
    Convert the alert to the NT8 payload format and send it.
    """
    ticker = alert["ticker"]
    action = alert["action"]
    current_position = alert["current_position"]
    qty = int(alert.get("qty", 1))
    price = float(alert.get("price", 0.0))
    trade_id = alert["trade_id"]
    time_str = alert["time"]

    # **Truncate the timestamp to minutes** (Updated)
    truncated_time_str = truncate_time_to_minute(time_str)

    # Convert ISO 8601 time to 'MM/dd/yyyy hh:mm:ss tt' in Eastern Time
    try:
        utc = pytz.utc
        eastern = pytz.timezone('US/Eastern')
        utc_time = datetime.fromisoformat(truncated_time_str.replace("Z", "")).replace(tzinfo=utc)
        est_time = utc_time.astimezone(eastern).strftime('%m/%d/%Y %I:%M:%S %p')
    except ValueError as e:
        print(f"Error converting time for alert with trade_id={trade_id}: {e}")
        return

    # Determine 'open' vs 'close' and direction for NT8
    if action == "buy":
        if current_position == "short":
            mapped_action = "close"
            direction = "short"
        else:
            mapped_action = "open"
            direction = "long"
    elif action == "sell":
        if current_position == "long":
            mapped_action = "close"
            direction = "long"
        else:
            mapped_action = "open"
            direction = "short"
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

    # Log the payload
    print("\n=== Processing Alert ===")
    print(json.dumps(alert, indent=4))
    print("=== Payload to NT8 ===")
    print(json.dumps(payload, indent=4))
    print("========================\n")

    # Forward the alert to relevant ports
    for strategy_name, strategy_data in config['strategies'].items():
        if ticker in strategy_data['tickers']:
            ports = strategy_data['tickers'][ticker]['ports']
            for port in ports:
                send_data_to_nt8(port, payload)

# -----------------------------------------------------------------------------------
# Start Background Processor Thread
# -----------------------------------------------------------------------------------
threading.Thread(target=background_processor, daemon=True).start()

# -----------------------------------------------------------------------------------
# Decorators
# -----------------------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session or not session['logged_in']:
            flash('You need to be logged in to view this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# -----------------------------------------------------------------------------------
# Routes
# -----------------------------------------------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Apply rate limit to prevent brute-force attacks
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Check if credentials match (hardcoded here for simplicity)
        if username == 'emyeele' and password == 'J3sussecured':  # Replace with a secure mechanism
            session['logged_in'] = True
            flash('You are now logged in.', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials. Please try again.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    session.pop('logged_in', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/clear_config', methods=['POST'])
@login_required
@limiter.limit("10 per minute")  # Apply rate limit to prevent abuse
def clear_config_route():
    global config
    config = {"strategies": {}}
    save_config()
    flash('Configuration cleared successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/', methods=['GET'])
@login_required
@limiter.limit("30 per minute")  # Apply rate limit to prevent abuse
def index():
    ensure_strategy_data_integrity()
    return render_template('index.html', config=config)

@app.route('/add_strategy', methods=['POST'])
@login_required
@limiter.limit("10 per minute")  # Apply rate limit to prevent abuse
def add_strategy():
    strategy_name = request.form.get('strategy_name')
    if strategy_name and strategy_name not in config['strategies']:
        config['strategies'][strategy_name] = {"accounts": {}, "tickers": {}}
        save_config()
        flash(f"Strategy '{strategy_name}' added successfully.", 'success')
    else:
        flash(f"Strategy '{strategy_name}' already exists or is invalid.", 'danger')
    return redirect(url_for('index'))

@app.route('/delete_strategy/<strategy>', methods=['POST'])
@login_required
@limiter.limit("10 per minute")  # Apply rate limit to prevent abuse
def delete_strategy(strategy):
    if strategy in config['strategies']:
        del config['strategies'][strategy]
        save_config()
        flash(f"Strategy '{strategy}' deleted successfully.", 'success')
    else:
        flash(f"Strategy '{strategy}' not found.", 'danger')
    return redirect(url_for('index'))

@app.route('/add_ticker/<strategy>', methods=['POST'])
@login_required
@limiter.limit("10 per minute")  # Rate limit for adding tickers
def add_ticker(strategy):
    if strategy not in config['strategies']:
        flash(f"Strategy '{strategy}' not found.", 'danger')
        return redirect(url_for('index'))
   
    ticker_name = request.form.get('ticker_name')
    if not ticker_name:
        flash("Ticker name cannot be empty.", 'danger')
        return redirect(url_for('index'))

    if ticker_name in config['strategies'][strategy]['tickers']:
        flash(f"Ticker '{ticker_name}' already exists in strategy '{strategy}'.", 'danger')
        return redirect(url_for('index'))
   
    # Add the new ticker to the strategy
    config['strategies'][strategy]['tickers'][ticker_name] = {"ports": []}
    save_config()
    flash(f"Ticker '{ticker_name}' added to strategy '{strategy}' successfully.", 'success')
    return redirect(url_for('index'))

@app.route('/delete_ticker/<strategy>/<ticker>', methods=['POST'])
@login_required
@limiter.limit("10 per minute")  # Apply rate limit to prevent abuse
def delete_ticker(strategy, ticker):
    if strategy in config['strategies'] and ticker in config['strategies'][strategy]['tickers']:
        del config['strategies'][strategy]['tickers'][ticker]
        save_config()
        flash(f"Ticker '{ticker}' deleted from strategy '{strategy}' successfully.", 'success')
    else:
        flash(f"Strategy or ticker not found.", 'danger')
    return redirect(url_for('index'))

@app.route('/add_port/<strategy>/<ticker>', methods=['POST'])
@login_required
@limiter.limit("10 per minute")  # Apply rate limit to prevent abuse
def add_port(strategy, ticker):
    if strategy in config['strategies'] and ticker in config['strategies'][strategy]['tickers']:
        port = request.form.get('port')
        if port and port not in config['strategies'][strategy]['tickers'][ticker]['ports']:
            config['strategies'][strategy]['tickers'][ticker]['ports'].append(port)
            # Sort ports numerically (if they're numeric)
            try:
                config['strategies'][strategy]['tickers'][ticker]['ports'].sort(key=int)
            except ValueError:
                pass
            save_config()
            flash(f"Port '{port}' added to ticker '{ticker}' in strategy '{strategy}' successfully.", 'success')
        else:
            flash(f"Port '{port}' already exists or is invalid.", 'danger')
    else:
        flash(f"Strategy or ticker not found.", 'danger')
    return redirect(url_for('index'))

@app.route('/delete_port/<strategy>/<ticker>/<port>', methods=['POST'])
@login_required
@limiter.limit("10 per minute")  # Apply rate limit to prevent abuse
def delete_port(strategy, ticker, port):
    if strategy in config['strategies'] and ticker in config['strategies'][strategy]['tickers']:
        if port in config['strategies'][strategy]['tickers'][ticker]['ports']:
            config['strategies'][strategy]['tickers'][ticker]['ports'].remove(port)
            save_config()
            flash(f"Port '{port}' deleted successfully.", 'success')
        else:
            flash(f"Port '{port}' not found.", 'danger')
    else:
        flash(f"Strategy or ticker not found.", 'danger')
    return redirect(url_for('index'))

# -----------------------------------------------------------------------------------
# Webhook Route
# -----------------------------------------------------------------------------------
@app.route('/webhook', methods=['POST'])
@limiter.limit("20 per minute")  # Rate limit webhook to prevent potential abuse
def webhook():
    data = request.json
    if not data:
        print("No data received.")
        return jsonify({'status': 'error', 'message': 'No data provided'}), 400

    # Log the received data
    print("\n=== Received Webhook Alert ===")
    print(json.dumps(data, indent=4))
    print("================================\n")

    # Basic validations
    required_fields = ["ticker", "action", "current_position", "qty", "price", "new_pos", "trade_id", "time"]
    for f in required_fields:
        if f not in data:
            return jsonify({'status': 'error', 'message': f"Missing required field: {f}"}), 400

    ticker = data["ticker"]
    time_str = data["time"]
    trade_id = data["trade_id"]
    numeric_id = extract_numeric_id(trade_id)

    # **Truncate the timestamp to minutes** (Updated)
    truncated_time_str = truncate_time_to_minute(time_str)

    key = (ticker, truncated_time_str)

    with lock:
        # Check if this (ticker, truncated_time_str, numeric_id) has already been discarded or processed
        if (ticker, truncated_time_str, numeric_id) in discarded_numeric_ids:
            processed_trade_ids.add(trade_id)
            print(f"Alert with numeric_id={numeric_id}, trade_id={trade_id} was previously discarded/processed. Skipping.")
            return jsonify({'status': 'skipped', 'message': 'Numeric ID previously discarded or processed'}), 200

        # Check if an alert with the same numeric_id is already pending within the same (ticker, truncated_time_str)
        existing_alerts = pending_alerts.get(key, [])
        conflict_found = False
        for alert_entry in existing_alerts:
            existing_trade_id = alert_entry['data']['trade_id']
            existing_numeric_id = extract_numeric_id(existing_trade_id)
            if existing_numeric_id == numeric_id:
                conflict_found = True
                break

        if conflict_found:
            # Discard both alerts with the same numeric_id within the same (ticker, truncated_time_str)
            print(f"Discarding both alerts for (ticker={ticker}, time={truncated_time_str}, numeric_id={numeric_id}) due to conflict.")
            # Discard existing alerts with the conflicting numeric_id
            for alert_entry in existing_alerts:
                existing_trade_id = alert_entry['data']['trade_id']
                processed_trade_ids.add(existing_trade_id)
                discarded_numeric_ids.add((ticker, truncated_time_str, numeric_id))  # **Updated**
                print(f"Discarding alert with trade_id={existing_trade_id}.")
            # Discard the new alert as well
            processed_trade_ids.add(trade_id)
            discarded_numeric_ids.add((ticker, truncated_time_str, numeric_id))  # **Updated**
            # Remove all alerts with the conflicting numeric_id
            pending_alerts[key] = [alert for alert in existing_alerts if extract_numeric_id(alert['data']['trade_id']) != numeric_id]
            return jsonify({'status': 'discarded', 'message': 'Conflicting alerts discarded'}), 200

        # No conflict, enqueue the alert with arrival time
        alert_entry = {
            'data': data,
            'arrival_time': time.time()
        }
        pending_alerts[key].append(alert_entry)
        print(f"Enqueued alert for (ticker={ticker}, time={truncated_time_str}, numeric_id={numeric_id}). Awaiting processing.")

    return jsonify({'status': 'success', 'message': 'Alert queued and will be processed shortly'}), 200

# -----------------------------------------------------------------------------------
# Main Entrypoint
# -----------------------------------------------------------------------------------
if __name__ == '__main__':
    app.run(port=5000, debug=True)
