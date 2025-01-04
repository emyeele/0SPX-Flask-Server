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

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Secure random key for session management

# Initialize configuration
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

# Decorator to require login for routes
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session or not session['logged_in']:
            flash('You need to be logged in to view this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Route for login page with rate limit
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

# Route for logout
@app.route('/logout')
@login_required
def logout():
    session.pop('logged_in', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

# Route to clear the configuration
@app.route('/clear_config', methods=['POST'])
@login_required
@limiter.limit("10 per minute")  # Apply rate limit to prevent abuse
def clear_config():
    global config
    config = {"strategies": {}}
    save_config()
    flash('Configuration cleared successfully!', 'success')
    return redirect(url_for('index'))

# Route for the home page
@app.route('/', methods=['GET'])
@login_required
@limiter.limit("30 per minute")  # Apply rate limit to prevent abuse
def index():
    ensure_strategy_data_integrity()
    return render_template('index.html', config=config)

# Route to add a new strategy
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

# Route to delete a strategy
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

# Route to add a ticker to a strategy
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

# Route to delete a ticker from a strategy
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

# Route to add a port to a ticker
@app.route('/add_port/<strategy>/<ticker>', methods=['POST'])
@login_required
@limiter.limit("10 per minute")  # Apply rate limit to prevent abuse
def add_port(strategy, ticker):
    if strategy in config['strategies'] and ticker in config['strategies'][strategy]['tickers']:
        port = request.form.get('port')
        if port and port not in config['strategies'][strategy]['tickers'][ticker]['ports']:
            config['strategies'][strategy]['tickers'][ticker]['ports'].append(port)
            config['strategies'][strategy]['tickers'][ticker]['ports'].sort(key=int)
            save_config()
            flash(f"Port '{port}' added to ticker '{ticker}' in strategy '{strategy}' successfully.", 'success')
        else:
            flash(f"Port '{port}' already exists or is invalid.", 'danger')
    else:
        flash(f"Strategy or ticker not found.", 'danger')
    return redirect(url_for('index'))

# Route to delete a port from a ticker
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

# Webhook route to receive alerts
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
    print("==============================\n")

    # Convert the ISO 8601 time to 'MM/dd/yyyy hh:mm:ss tt' format in Eastern Time
    iso_time = data.get("time")
    try:
        # Define timezones
        utc = pytz.utc
        eastern = pytz.timezone('US/Eastern')

        # Parse the ISO time and convert to Eastern Time
        utc_time = datetime.fromisoformat(iso_time.replace("Z", "")).replace(tzinfo=utc)
        est_time = utc_time.astimezone(eastern).strftime('%m/%d/%Y %I:%M:%S %p')
        print(f"Converted time for NT8: {est_time}")
    except ValueError as e:
        print(f"Error converting time: {e}")
        return jsonify({'status': 'error', 'message': 'Invalid time format'}), 400

    # Map received data to NT8 expected fields
    received_action = data.get("action")
    current_position = data.get("current_position")

    # Updated action and direction mapping logic
    if received_action == "buy":
        if current_position == "short":
            # Close short position first
            mapped_action = "close"
            direction = "short"
        else:
            # Open long position
            mapped_action = "open"
            direction = "long"
    elif received_action == "sell":
        if current_position == "long":
            # Close long position first
            mapped_action = "close"
            direction = "long"
        else:
            # Open short position
            mapped_action = "open"
            direction = "short"
    else:
        return jsonify({'status': 'error', 'message': 'Unknown action type'}), 400

    # Create the payload for NT8
    payload = {
        "ticker": data.get("ticker"),
        "action": mapped_action,
        "direction": direction,
        "qty": int(data.get("qty", 1)),
        "price": float(data.get("price", 0.0)),
        "time": est_time
    }

    # Log the payload being sent to NinjaTrader
    print("\n=== Payload Sent to NT8 ===")
    print(json.dumps(payload, indent=4))
    print("===========================\n")

    # Forward the alert to relevant ports
    for strategy_name, strategy_data in config['strategies'].items():
        if payload["ticker"] in strategy_data['tickers']:
            ports = strategy_data['tickers'][payload["ticker"]]['ports']
            for port in ports:
                send_data_to_nt8(port, payload)

    return jsonify({'status': 'success', 'message': 'Alert received and forwarded'}), 200

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

# Helper function to save the configuration
def save_config():
    with open(config_path, 'w') as f:
        json.dump(config, f, indent=4)

# Ensure all strategies have the necessary attributes initialized
def ensure_strategy_data_integrity():
    for strategy_name, strategy_data in config["strategies"].items():
        if "accounts" not in strategy_data:
            strategy_data["accounts"] = {}
        if "tickers" not in strategy_data:
            strategy_data["tickers"] = {}

if __name__ == '__main__':
    app.run(port=5000, debug=True)
