# Pause or resume a Nessus scan based on a schedule set by the user

import requests
import json
import time
import sys
from argparse import ArgumentParser, Namespace
import os
from dotenv import load_dotenv

# Disable SSL warnings
requests.packages.urllib3.disable_warnings()
INFO = "\033[93m[!]"
ERR = "\033[91m[-]"
SUCCESS = "\033[92m[+]"
RESET = "\033[0m"
BOLD = "\033[1m"


def print_info(message):
    """Print an info message"""
    print(f"{INFO} INFO: {message}{RESET}")


def print_error(message):
    """Print an error message"""
    print(f"{ERR} ERROR: {message}{RESET}")


def print_success(message):
    """Print a success message"""
    print(f"{SUCCESS} SUCCESS: {message}{RESET}")


dotenv_path = ".env"
load_dotenv(dotenv_path)


def get_args() -> Namespace:
    parser = ArgumentParser(description="Pause or resume a Nessus scan based on a schedule set by the user")
    parser.add_argument("-s", "--server", required=True, action="store", help="Nessus server IP address or hostname")
    parser.add_argument(
        "-p", "--port", required=False, action="store", help="Nessus server port (default: 8834)", default=8834
    )
    parser.add_argument(
        "-aT",
        "--api_token",
        action="store",
        default=os.getenv("NESSUS_API_TOKEN"),
        help="Nessus API token (defaults to NESSUS_API_TOKEN in .env file)",
        type=str,
    )
    parser.add_argument(
        "-c",
        "--x_cookie",
        action="store",
        default=os.getenv("NESSUS_X_COOKIE"),
        help="Nessus X-Cookie (defaults to NESSUS_X_COOKIE in .env file)",
        type=str,
    )
    parser.add_argument("-S", "--scan_id", required=True, action="store", help="Nessus scan ID")
    parser.add_argument(
        "-a",
        "--action",
        required=True,
        action="store",
        help="Action to perform",
        type=str,
        choices=["pause", "resume", "check"],
    )
    parser.add_argument(
        "-t", "--time", action="store", help="Time to pause or resume the scan (format: YYYY-MM-DD HH:MM)"
    )
    parser.add_argument(
        "-tT",
        "--telegramToken",
        action="store",
        default=os.getenv("TELEGRAM_BOT_TOKEN"),
        help="Telegram bot token (defaults to TELEGRAM_BOT_TOKEN in .env file)",
        type=str,
    )
    parser.add_argument(
        "-tC",
        "--telegramChatID",
        action="store",
        default=os.getenv("TELEGRAM_CHAT_ID"),
        help="Telegram chat ID (defaults to TELEGRAM_CHAT_ID in .env file)",
        type=str,
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    args = parser.parse_args()
    return args


def get_scan_status(args):
    url = f"https://{args.server}:{args.port}/scans/{args.scan_id}"
    headers = {"X-Api-Token": args.api_token, "X-Cookie": f"token={args.x_cookie}"}
    response = requests.get(url, headers=headers, verify=False)
    scan = json.loads(response.text)
    if response.status_code != 200:
        return {"status": scan['error'], "name": "error", "response_code": response.status_code}
    return {"status": scan["info"]["status"], "name": scan["info"]["name"], "response_code": response.status_code}


def scan_actions(args: Namespace) -> None:
    if args.action == "pause" or args.action == "resume":
        url = f"https://{args.server}:{args.port}/scans/{args.scan_id}/{args.action}"
        headers = {"X-Api-Token": args.api_token, "X-Cookie": f"token={args.x_cookie}"}
        response = requests.post(url, headers=headers, verify=False)
        if response.status_code != 200:
            print_error(f'Status code {response.status_code} - {json.loads(response.text)["error"]}')
            if args.telegramToken and args.telegramChatID:
                telegram_bot_sendtext(
                    f"Nessus Error: {response.status_code} - Scan {args.scan_id} not {args.action}",
                    args.telegramToken,
                    args.telegramChatID,
                )
            sys.exit(1)
        print(f"Scan {args.action}d")
    else:
        print_error('Invalid action specified (must be "pause" or "resume")')
        sys.exit(1)


# Send telegram message
def telegram_bot_sendtext(bot_message: str, args: Namespace) -> None:
    # check if telegramToken and telegramChatID are set if action is not check
    if args.telegramToken == None or args.telegramChatID == None and args.action not in ["check"]:
        telegram_message = bot_message.replace(" ", "%20")
        telegram_url = f"https://api.telegram.org/bot{args.telegramToken}/sendMessage?chat_id={args.telegramChatID}&text={telegram_message}"
        try:
            response = requests.get(telegram_url)
            return response.json()
        except:
            print("Error sending telegram message. Check token and chat ID")
            sys.exit(1)
    else:
        return


def main():
    args = get_args()

    # check if api_token and x_cookie are set
    if args.api_token == None or args.x_cookie == None:
        print_error(f"API token and X-Cookie are required to run these actions if not set in {dotenv_path} file")
        sys.exit(1)

    check = get_scan_status(args)
    status = check["status"]
    name = check["name"]
    response_code = check["response_code"]
    if response_code != 200:
        print_error(f'Status code {response_code} - {status}')
        sys.exit(1)
    
    if args.verbose:
        print_success(f"X-API-Token and X-Cookie work!")
    print_info(f'Scan "{name}" status: {BOLD}{status}{RESET}')
    if args.action == "check":
        sys.exit(0)

    if status == "running" and args.action == "resume":
        print_error("Scan is already running")
        sys.exit(1)
    elif status == "paused" and args.action == "pause":
        print_error("Scan is already paused")
        sys.exit(1)
    # schedule a scan to pause or resume if time is specified

    # check if time is specified and if it is in the correct format
    if (
        args.time
        and len(args.time) != 16
        and args.time[4] != "-"
        and args.time[7] != "-"
        and args.time[10] != " "
        and args.time[13] != ":"
    ):
        print_error("Invalid time format (YYYY-MM-DD HH:MM)")
        sys.exit(1)

    if args.time:
        telegram_bot_sendtext(f"Nessus: Scan {name} has been tasked to {args.action} at {args.time}", args)
        if args.verbose:
            print_info(f"Scan {name} has been tasked to {args.action} at {args.time}")
        while True:
            current_time = time.strftime("%Y-%m-%d %H:%M")
            if current_time == args.time:
                break
            time.sleep(50)

    scan_actions(args)
    now_time = time.strftime("%Y-%m-%d %H:%M")
    if args.verbose:
        print_info(f'{args.action.capitalize().split("e")[0]}ing scan')
    telegram_bot_sendtext(f"Nessus: Scan {name} has been tasked to {args.action} at {now_time}", args)

    # check if scan is running or paused and wait until it is paused or running
    while True:
        check = get_scan_status(args)
        status = check["status"]
        name = check["name"]
        response_code = check["response_code"]
        # Error handling
        if response_code != 200:
            print_error(f'Status code {response_code} - {status}')
            telegram_bot_sendtext(
                f"Nessus Error: {response_code} - Scan {args.scan_id} not {args.action}d. Reason: {status}",
                args.telegramToken,
                args.telegramChatID,
            )
            sys.exit(1)
        elif status == "running" and args.action == "pause":
            time.sleep(60)
        elif status == "paused" and args.action == "resume":
            time.sleep(60)
        else:
            break

    now_time = time.strftime("%Y-%m-%d %H:%M")
    print_success(f'Scan "{name}" {args.action}d')
    telegram_bot_sendtext(f"Nessus: Scan {name} {args.action}d at {now_time}", args)

if __name__ == "__main__":
    main()
