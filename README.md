# 0SPX Flask Server

This Flask-based application serves as a robust server for managing trading alerts and strategies. It processes incoming webhook alerts, organizes and forwards them to appropriate ports for integration with **NinjaTrader**, and provides a user interface for managing strategies, tickers, and ports.

## Key Features

1. **Webhook Alert Management**:

   - Receives trading alerts via a webhook.
   - Deduplicates alerts and processes them with a configurable delay.

2. **Strategy and Ticker Management**:

   - Add, delete, and manage trading strategies and their associated tickers.
   - Assign and manage ports for each ticker.

3. **Rate Limiting**:

   - Limits API calls to ensure system stability (default: 200 per day, 50 per hour).

4. **Background Processing**:

   - A background thread handles alert processing asynchronously.

5. **User Interface**:

   - Simple web-based UI for managing strategies, tickers, and ports.

6. **Time Zone Conversion**:

   - Converts timestamps from UTC to Eastern Time (US).

7. **Logging**:

   - Comprehensive logging for debugging and operational visibility.

## Installation

### Prerequisites:

- Python 3.8 or higher
- Pip (Python package manager)

### Steps:

1. Clone the repository:

   ```bash
   git clone https://github.com/emyeele/0SPX-Flak-Server.git  
   cd 0SPX-Flak-Server  
   ```

2. Install dependencies:

   ```bash
   pip install -r requirements.txt  
   ```

3. Create a `config.json` file for storing strategy configurations:

   ```json
   {
       "strategies": {}
   }
   ```

4. Run the server:

   ```bash
   python app.py  
   ```

## Usage

### Webhook Endpoint

- **Endpoint**: `/webhook`
- **Method**: `POST`
- **Payload example**:
  ```json
  {
      "ticker": "AAPL",
      "trade_id": "Open_Long_ID_123",
      "action": "buy",
      "current_position": "short",
      "qty": 10,
      "price": 150.25,
      "time": "2024-01-04T15:30:00Z"
  }
  ```
- **Response**:
  - Success: `{"status": "success", "message": "Alert queued"}`
  - Duplicate Alert: `{"status": "skipped", "message": "Duplicate alert"}`

### Management UI

- **Access the management UI at the root endpoint**: `/`
- **Features**:
  - Add, delete, and manage strategies.
  - Add, delete, and assign tickers and ports to strategies.

## Configuration

### `config.json` Structure

```json
{
    "strategies": {
        "StrategyName": {
            "accounts": {},
            "tickers": {
                "TickerName": {
                    "ports": [5001, 5002]
                }
            }
        }
    }
}
```

### Example:

```json
{
    "strategies": {
        "MomentumStrategy": {
            "accounts": {},
            "tickers": {
                "AAPL": {
                    "ports": [5000]
                },
                "TSLA": {
                    "ports": [5001, 5002]
                }
            }
        }
    }
}
```

## Development

### Rate Limiting

- **Default limits**:
  - `200 requests/day`
  - `50 requests/hour`
- **Modify limits in \*\*\*\*****`app.py`**:
  ```python
  limiter = Limiter(
      get_remote_address,
      app=app,
      default_limits=["200 per day", "50 per hour"]
  )
  ```

### Background Processor

- **Configurable delay before processing alerts (********`DELAY_SECONDS`********)**:
  ```python
  DELAY_SECONDS = 2
  ```

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Contact

For support or inquiries, contact Mike Orcel @ MikeOrcel\@gmail.com
