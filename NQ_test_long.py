import requests
import threading

# Correct URL of your Flask server endpoint
FLASK_SERVER_URL = "https://0spx.ngrok.io/webhook"  # Updated to the correct endpoint

# JSON payloads for the two alerts with the same ticker
alert_1 = {
    "ticker": "TEST-NQ_long",
    "action": "buy",
    "current_position": "flat",
    "qty": "1",
    "price": "2246.5",
    "new_pos": "long",
    "trade_id": "Open_Short_ID_8",
    "time": "2025-01-03T00:36:10Z"
}

alert_2 = {
    "ticker": "TEST-NQ_long",
    "action": "sell",
    "current_position": "long",
    "qty": "1",
    "price": "2246.5",
    "new_pos": "flat",
    "trade_id": "Close_Short_ID_8",
    "time": "2025-01-03T00:36:20Z"
}

# Function to send a JSON alert
def send_alert(alert):
    try:
        response = requests.post(FLASK_SERVER_URL, json=alert)
        print(f"Response for {alert['ticker']} with action {alert['action']}: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"Error sending alert {alert['ticker']} with action {alert['action']}: {e}")

# Threads to send alerts simultaneously
thread_1 = threading.Thread(target=send_alert, args=(alert_1,))
thread_2 = threading.Thread(target=send_alert, args=(alert_2,))

# Start both threads
thread_1.start()
thread_2.start()

# Wait for both threads to complete
thread_1.join()
thread_2.join()

print("Both alerts have been sent.")
