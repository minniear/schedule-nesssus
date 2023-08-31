# Schedule Nessus

## Description
This script will schedule a scan in Nessus that has already been created and has already been started. This script was initially made for me to not have to log into Nessus every time I wanted to pause/resume a scan. This script will also allow you to schedule a scan to be paused/resumed at a specific time. It also will send out Telegram notifications when a scan has been paused/resumed.

## Requirements
- Python 3
- Nessus Professional or Nessus Manager
- Telegram Bot (optional)

## Installation
1. Clone this repository
```bash
git clone https://github.com/minniear/schedule-nesssus.git
```
2. Install the requirements, preferably in a virtual environment
```bash
python3 -m venv schedule-nessus
cd schedule-nessus
source bin/activate
pip3 install -r requirements.txt
```
3. Create a Telegram Bot (optional)
4. Create a .env file and add your API keys and other variables (see below) (optional)
5. Run the script

## Usage
```
usage: schedule-nessus.py [-h] -s SERVER [-p PORT] [-aT API_TOKEN] [-c X_COOKIE] -S SCAN_ID -a {pause,resume,check} [-t TIME] [-tT TELEGRAMTOKEN] [-tC TELEGRAMCHATID] [-v]

Pause or resume a Nessus scan based on a schedule set by the user

options:
  -h, --help            show this help message and exit
  -s SERVER, --server SERVER
                        Nessus server IP address or hostname
  -p PORT, --port PORT  Nessus server port (default: 8834)
  -aT API_TOKEN, --api_token API_TOKEN
                        Nessus API token (defaults to NESSUS_API_TOKEN in .env file)
  -c X_COOKIE, --x_cookie X_COOKIE
                        Nessus X-Cookie (defaults to NESSUS_X_COOKIE in .env file)
  -S SCAN_ID, --scan_id SCAN_ID
                        Nessus scan ID
  -a {pause,resume,check}, --action {pause,resume,check}
                        Action to perform
  -t TIME, --time TIME  Time to pause or resume the scan (format: YYYY-MM-DD HH:MM)
  -tT TELEGRAMTOKEN, --telegramToken TELEGRAMTOKEN
                        Telegram bot token (defaults to TELEGRAM_BOT_TOKEN in .env file)
  -tC TELEGRAMCHATID, --telegramChatID TELEGRAMCHATID
                        Telegram chat ID (defaults to TELEGRAM_CHAT_ID in .env file)
  -v, --verbose         Enable verbose output
```

## .env file
```
TELEGRAM_BOT_TOKEN="1234567890:ABCDEF1234567890"
TELEGRAM_CHAT_ID="1234567890"
NESSUS_API_TOKEN="1a2b3c4d-1a2b-3c4d-1a2b-3c4d1a2b3c4d"
NESSUS_X_COOKIE="1a2b3c4d1a2b3c4d1a2b3c4d1a2b3c4d1a2b3c4d1a2b3c4d"
```

## Examples
```
python3 schedule-nessus.py -s 192.168.250.158 -S 13 -a check
```
```
python3 schedule-nessus.py -s 10.10.10.10 -p 8080 -S 11 -a pause -t "2021-01-01 00:00" -tT "1234567890:ABCDEF1234567890" -tC "1234567890" -aT "1a2b3c4d-1a2b-3c4d-1a2b-3c4d1a2b3c4d" -c "1a2b3c4d1a2b3c4d1a2b3c4d1a2b3c4d1a2b3c4d1a2b3c4d" -v
```

## How to get the Nessus API token and X-Cookie
1. Log into Nessus
2. Open the developer tools in your browser
3. Go to the Network tab
4. Either pause or resume a scan
5. Look for the POST request to pause or resume and click on it
6. From the Headers tab, copy the X-Cookie value **AFTER** "token=" and paste it into the .env file
7. From the Headers tab, copy the X-API-Token value and paste it into the .env file
8. Also note the scan ID from the URL (e.g. https://nessus.example.com/#/scans/reports/11/hosts)

## How to get the Telegram bot token and chat ID
1. Start a chat with the BotFather
2. Send the BotFather the start message `/start`
3. Send the BotFather the newbot message `/newbot`
4. Answer the BotFather's questions to finsh setting up the bot. Keep in mind that your bot name will be searchable by all Telegram users.
5. Save your bot's API key for future reference.
6. Start a chat with your bot and then navigate to <https://api.telegram.org/bot123456789:jbd78sadvbdy63d37gda37bd8/getUpdates> and replace your API key in the URL. **IT NEEDS TO START WITH 'bot' SO KEEP THAT PART OF THE URL**.
7. You will likely get a blank result until you send your bot another message and refresh the getUpdates URL.
8. Once you see updates from the URL, note your 'chat_id'. You can use the combination of chat ID and your API key to send automated alerts.
    - EXAMPLE: `curl "https://api.telegram.org/bot123456789:jbd78sadvbdy63d37gda37bd8/sendMessage?chat_id=123456&text=%22You just got a shell! Go check your C2 server!%22"`
9. Copy the "id" value and paste it into the .env file
10. Copy the "token" value and paste it into the .env file




