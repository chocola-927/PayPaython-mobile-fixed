import requests
from uuid import uuid4
import pkce
import random
from typing import NamedTuple, Optional
import time
import os

# aws waf 突破ヘルパーを追加（このモジュールをリポジトリ内に置いてください）
from .waf_helper import solve_aws_waf

# 制御用環境変数
SKIP_WAF = os.getenv("PAYPAY_SKIP_WAF", "0") == "1"
DEBUG = os.getenv("PAYPAY_DEBUG", "0") == "1"

def _debug(*args, **kwargs):
    if DEBUG:
        print("[PayPay-debug]", *args, **kwargs)

''' Optional sentry generation helper (kept as in upstream)
def generate_sentry():
    ...
'''

def generate_vector(r1, r2, r3, precision=8):
    v1 = f"{random.uniform(*r1):.{precision}f}"
    v2 = f"{random.uniform(*r2):.{precision}f}"
    v3 = f"{random.uniform(*r3):.{precision}f}"
    return f"{v1}_{v2}_{v3}"

def generate_device_state():
    device_orientation = generate_vector(
        (2.2, 2.6),
        (-0.2, -0.05),
        (-0.05, 0.1)
    )
    device_orientation_2 = generate_vector(
        (2.0, 2.6),
        (-0.2, -0.05),
        (-0.05, 0.2)
    )
    device_rotation = generate_vector(
        (-0.8, -0.6),
        (0.65, 0.8),
        (-0.12, -0.04)
    )
    device_rotation_2 = generate_vector(
        (-0.85, -0.4),
        (0.53, 0.9),
        (-0.15, -0.03)
    )
    device_acceleration = generate_vector(
        (-0.35, 0.0),
        (-0.01, 0.3),
        (-0.1, 0.1)
    )
    device_acceleration_2 = generate_vector(
        (0.01, 0.04),
        (-0.04, 0.09),
        (-0.03, 0.1)
    )
    class DeviceHeaders(NamedTuple):
        device_orientation: str
        device_orientation_2: str
        device_rotation: str
        device_rotation_2: str
        device_acceleration: str
        device_acceleration_2: str

    return DeviceHeaders(
        device_orientation,
        device_orientation_2,
        device_rotation,
        device_rotation_2,
        device_acceleration,
        device_acceleration_2
    )

def update_header_device_state(headers: dict):
    device_state = generate_device_state()
    headers["Device-Orientation"] = device_state.device_orientation
    headers["Device-Orientation-2"] = device_state.device_orientation_2
    headers["Device-Rotation"] = device_state.device_rotation
    headers["Device-Rotation-2"] = device_state.device_rotation_2
    headers["Device-Acceleration"] = device_state.device_acceleration
    headers["Device-Acceleration-2"] = device_state.device_acceleration_2
    return headers

class PayPayError(Exception):
    pass

class PayPayLoginError(Exception):
    pass

class PayPayNetWorkError(Exception):
    pass

def _try_solve_waf(session, user_agent: str, proxy: Optional[dict], retries: int = 2, wait: float = 0.5) -> Optional[str]:
    """
    単純なリトライラッパー。成功すれば token を返す。
    SKIP_WAF が真なら何もしない（None返却）。
    """
    if SKIP_WAF:
        _debug("SKIP_WAF enabled, not attempting WAF solve.")
        return None

    last_exc = None
    for i in range(retries):
        try:
            token = solve_aws_waf(
                session,
                check_url="https://www.paypay.ne.jp/portal/oauth2/sign-in",
                domain="www.paypay.ne.jp",
                user_agent=user_agent,
                proxy=proxy,
                timeout=30
            )
            if token:
                _debug("aws-waf-token obtained")
                return token
        except Exception as e:
            last_exc = e
            _debug(f"awswaf attempt {i+1} failed:", repr(e))
        time.sleep(wait)
    _debug("awswaf attempts exhausted; returning None")
    return None

class PayPay():
    def __init__(self, phone: str = None, password: str = None, device_uuid: str = None,
                 client_uuid: str = str(uuid4()), access_token: str = None, proxy=None):
        if phone and "-" in phone:
            phone = phone.replace("-", "")

        self.session = requests.Session()
        self.proxy = None
        if isinstance(proxy, str):
            if not proxy.startswith("http"):
                proxy = "http://" + proxy
            self.proxy = {"https": proxy, "http": proxy}
        elif isinstance(proxy, dict):
            self.proxy = proxy
        else:
            self.proxy = proxy

        self.device_uuid = device_uuid or str(uuid4())
        self.client_uuid = client_uuid
        self.params = {"payPayLang": "ja"}

        self.version = "5.11.1"
        device_state = generate_device_state()
        self.headers = {
            "Accept": "*/*",
            "Accept-Charset": "UTF-8",
            "Accept-Encoding": "gzip",
            "Client-Mode": "NORMAL",
            "Client-OS-Release-Version": "10",
            "Client-OS-Type": "ANDROID",
            "Client-OS-Version": "29.0.0",
            "Client-Type": "PAYPAYAPP",
            "Client-UUID": self.client_uuid,
            "Client-Version": self.version,
            "Connection": "Keep-Alive",
            "Content-Type": "application/x-www-form-urlencoded",
            "Device-Acceleration": device_state.device_acceleration,
            "Device-Acceleration-2": device_state.device_acceleration_2,
            "Device-Brand-Name": "KDDI",
            "Device-Hardware-Name": "qcom",
            "Device-In-Call": "false",
            "Device-Lock-App-Setting": "false",
            "Device-Lock-Type": "NONE",
            "Device-Manufacturer-Name": "samsung",
            "Device-Name": "SCV38",
            "Device-Orientation": device_state.device_orientation,
            "Device-Orientation-2": device_state.device_orientation_2,
            "Device-Rotation": device_state.device_rotation,
            "Device-Rotation-2": device_state.device_rotation_2,
            "Device-UUID": self.device_uuid,
            "Host": "app4.paypay.ne.jp",
            "Is-Emulator": "false",
            "Network-Status": "WIFI",
            "System-Locale": "ja",
            "Timezone": "Asia/Tokyo",
            "User-Agent": f"PaypayApp/{self.version} Android10"
        }

        if access_token:
            self.access_token = access_token
            self.headers["Authorization"] = f"Bearer {self.access_token}"
            self.headers["content-type"] = "application/json"
        else:
            self.access_token = None
            self.refresh_token = None

        # store provided login credentials for later use in flow
        self._init_phone = phone
        self._init_password = password

        def _prepare_oauth_par(self):
        """
        /bff/v2/oauth2/par の取得。戻り値は JSON か例外発生。
        code_verifier/code_challenge は self に保持する方式に修正。
        """
        # まだ code_verifier を持っていなければ生成して保持する
        if not hasattr(self, "code_verifier") or not hasattr(self, "code_challenge"):
            self.code_verifier, self.code_challenge = pkce.generate_pkce_pair(43)

        payload = {
            "clientId": "pay2-mobile-app-client",
            "clientAppVersion": self.version,
            "clientOsVersion": "29.0.0",
            "clientOsType": "ANDROID",
            "redirectUri": "paypay://oauth2/callback",
            "responseType": "code",
            "state": pkce.generate_code_verifier(43),
            "codeChallenge": self.code_challenge,
            "codeChallengeMethod": "S256",
            "scope": "REGULAR",
            "tokenVersion": "v2",
            "prompt": "",
            "uiLocales": "ja"
        }
        resp = self.session.post("https://app4.paypay.ne.jp/bff/v2/oauth2/par?payPayLang=ja",
                                 headers=self.headers, data=payload, proxies=self.proxy)
        try:
            return resp.json()
        except Exception:
            raise PayPayNetWorkError("日本以外からは接続できません")

    
    def login(self, url: str):
        """
        パラメータ: url は PayPay の OTL コードなど、もしくは OAuth の redirect id 部分。
        この関数は既存の login ロジックを再現しつつ、
        WAF チャレンジが出た場合に waf_helper を呼んでトークンを session に注入します。
        """
        if "https://" in url:
            url = url.replace("https://www.paypay.ne.jp/portal/oauth2/l?id=", "")

        phone = self._init_phone
        password = self._init_password

        headers = {
            "Accept": "application/json, text/plain, */*",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "ja-JP,ja;q=0.9",
            "Cache-Control": "no-cache",
            "Client-Id": "pay2-mobile-app-client",
            "Client-OS-Type": "ANDROID",
            "Client-OS-Version": "29.0.0",
            "Client-Type": "PAYPAYAPP",
            "Client-Version": self.version,
            "Connection": "keep-alive",
            "Content-Type": "application/json",
            "Host": "www.paypay.ne.jp",
            "Origin": "https://www.paypay.ne.jp",
            "Pragma": "no-cache",
            "Referer": f"https://www.paypay.ne.jp/portal/oauth2/l?id={url}&client_id=pay2-mobile-app-client",
            "sec-ch-ua": '"Not A(Brand";v="8", "Chromium";v="132", "Android WebView";v="132")',
            "sec-ch-ua-mobile": "?1",
            "sec-ch-ua-platform": '"Android"',
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
            "User-Agent": f"Mozilla/5.0 (Linux; Android 10; SCV38 Build/QP1A.190711.020; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/132.0.6834.163 Mobile Safari/537.36",
            "X-Requested-With": "jp.ne.paypay.android.app"
        }

        # 1) verify OTL code
        confirm_url = self.session.post(
            "https://www.paypay.ne.jp/portal/api/v2/oauth2/extension/sign-in/2fa/otl/verify",
            headers=headers, json={"code": url}, proxies=self.proxy
        ).json()
        if confirm_url["header"]["resultCode"] != "S0000":
            raise PayPayLoginError(confirm_url)

        # 2) complete OTL flow to get redirect uri
        payload = {
            "params": {
                "extension_id": "user-main-2fa-v1",
                "data": {
                    "type": "COMPLETE_OTL",
                    "payload": None
                }
            }
        }
        get_uri = self.session.post(
            "https://www.paypay.ne.jp/portal/api/v2/oauth2/extension/code-grant/update",
            headers=headers, json=payload, proxies=self.proxy
        ).json()
        if get_uri["header"]["resultCode"] != "S0000":
            raise PayPayLoginError(get_uri)

        try:
            uri = get_uri["payload"]["redirect_uri"].replace("paypay://oauth2/callback?", "").split("&")
        except Exception:
            raise PayPayLoginError('redirect_uriが見つかりませんでした\n' + str(get_uri))

        # 3) exchange code for tokens
        headers_token = self.headers.copy()
        del headers_token["Device-Lock-Type"]
        del headers_token["Device-Lock-App-Setting"]

        confirm_data = {
            "clientId": "pay2-mobile-app-client",
            "redirectUri": "paypay://oauth2/callback",
            "code": uri[0].replace("code=", ""),
            "codeVerifier": self.code_verifier if hasattr(self, "code_verifier") else ""
        }

        get_token = self.session.post(
            "https://app4.paypay.ne.jp/bff/v2/oauth2/token",
            headers=headers_token, data=confirm_data, params=self.params, proxies=self.proxy
        ).json()
        if get_token["header"]["resultCode"] != "S0000":
            raise PayPayLoginError(get_token)

        self.access_token = get_token["payload"]["accessToken"]
        self.refresh_token = get_token["payload"]["refreshToken"]
        self.headers["Authorization"] = f"Bearer {self.access_token}"
        self.headers["content-type"] = "application/json"
        self.headers = update_header_device_state(self.headers)

        return get_token

    def prepare_login_flow_with_waf(self, phone: str, password: str):
        """
        古い OAuth-like web フローを使う場合に呼び出すための高レベル準備関数。
        - par を取り、authorize → sign-in の箇所で WAF をチェックして突破を試みる。
        - 成功すれば session に aws-waf-token が入る。
        """
        # store credentials for login()
        self._init_phone = phone
        self._init_password = password

        # Prepare pkce code verifier/challenge for the flow
        self.code_verifier, self.code_challenge = pkce.generate_pkce_pair(43)

        # 1) request PAR
        payload = {
            "clientId": "pay2-mobile-app-client",
            "clientAppVersion": self.version,
            "clientOsVersion": "29.0.0",
            "clientOsType": "ANDROID",
            "redirectUri": "paypay://oauth2/callback",
            "responseType": "code",
            "state": pkce.generate_code_verifier(43),
            "codeChallenge": self.code_challenge,
            "codeChallengeMethod": "S256",
            "scope": "REGULAR",
            "tokenVersion": "v2",
            "prompt": "",
            "uiLocales": "ja"
        }
        par_resp = self.session.post("https://app4.paypay.ne.jp/bff/v2/oauth2/par?payPayLang=ja",
                                     headers=self.headers, data=payload, proxies=self.proxy)
        try:
            par = par_resp.json()
        except Exception:
            raise PayPayNetWorkError("日本以外からは接続できません")
        if par["header"]["resultCode"] != "S0000":
            raise PayPayLoginError(par)

        # build headers for web interactions
        web_headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate, br, zstd",
            "Accept-Language": "ja-JP,ja;q=0.9",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "Host": "www.paypay.ne.jp",
            "Pragma": "no-cache",
            "sec-ch-ua": '"Not A(Brand";v="8", "Chromium";v="132", "Android WebView";v="132"',
            "sec-ch-ua-mobile": "?1",
            "sec-ch-ua-platform": '"Android"',
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (Linux; Android 10; SCV38; wv) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132 Mobile Safari/537.36",
            "X-Requested-With": "jp.ne.paypay.android.app"
        }

        params = {
            "client_id": "pay2-mobile-app-client",
            "request_uri": par["payload"]["requestUri"]
        }

        # Before calling authorize, try WAF solve
        _debug("Attempting WAF solve before authorize")
        _try_solve_waf(self.session, self.headers.get("User-Agent"), self.proxy)

        # call authorize (this may set cookies/redirects)
        self.session.get("https://www.paypay.ne.jp/portal/api/v2/oauth2/authorize",
                         headers=web_headers, params=params, proxies=self.proxy)

        # try again immediately before sign-in
        _debug("Attempting WAF solve before sign-in")
        _try_solve_waf(self.session, self.headers.get("User-Agent"), self.proxy)

        # call sign-in landing (may trigger challenge page)
        sign_in_params = {"client_id": "pay2-mobile-app-client", "mode": "landing"}
        self.session.get("https://www.paypay.ne.jp/portal/oauth2/sign-in",
                         headers=web_headers, params=sign_in_params, proxies=self.proxy)

        # After this point, perform normal sign-in using self.login(url) with the OTL code
        _debug("prepare_login_flow_with_waf complete; continue with login() using obtained OTL/url")

    def get_history(self, size: int = 20, cashback: bool = False) -> dict:
        if not self.access_token:
            raise PayPayLoginError("まずはログインしてください")

        #self.headers=update_header_baggage(self.headers,sentry_public_key,"0.0099999997764826",False,"TransactionHistoryV2Fragment",0)

        params = {
            "pageSize": str(size),
            "orderTypes": "",
            "paymentMethodTypes": "",
            "signUpCompletedAt": "2021-01-02T10:16:24Z",
            "isOverdraftOnly": "false",
            "payPayLang": "ja"
        }
        if cashback:
            params["orderTypes"] = "CASHBACK"

        history = self.session.get("https://app4.paypay.ne.jp/bff/v3/getPaymentHistory",
                                   params=params, headers=self.headers, proxies=self.proxy).json()

        if history["header"]["resultCode"] == "S0001":
            raise PayPayLoginError(history)

        if history["header"]["resultCode"] != "S0000":
            raise PayPayError(history)

        return history
    
    def get_balance(self):
        if not self.access_token:
            raise PayPayLoginError("まずはログインしてください")

        #self.headers=update_header_baggage(self.headers,sentry_public_key,"0",False,"WalletAssetDetailsFragment")

        params = {
            "includePendingBonusLite": "false",
            "includePending": "true",
            "noCache": "true",
            "includeKycInfo": "true",
            "includePayPaySecuritiesInfo": "true",
            "includePointInvestmentInfo": "true",
            "includePayPayBankInfo": "true",
            "includeGiftVoucherInfo": "true",
            "payPayLang": "ja"
        }
        balance=self.session.get("https://app4.paypay.ne.jp/bff/v1/getBalanceInfo",headers=self.headers,params=params,proxies=self.proxy).json()

        if balance["header"]["resultCode"] == "S0001":
            raise PayPayLoginError(balance)
        
        if balance["header"]["resultCode"] != "S0000":
            raise PayPayError(balance)
        
        try:
            money=balance["payload"]["walletDetail"]["emoneyBalanceInfo"]["balance"]
        except:
            money=None

        class GetBalance(NamedTuple):
            money: int
            money_light: int
            all_balance: int
            useable_balance: int
            points: int
            raw: dict
        
        money_light=balance["payload"]["walletDetail"]["prepaidBalanceInfo"]["balance"]
        all_balance=balance["payload"]["walletSummary"]["allTotalBalanceInfo"]["balance"]
        useable_balance=balance["payload"]["walletSummary"]["usableBalanceInfoWithoutCashback"]["balance"]
        points=balance["payload"]["walletDetail"]["cashBackBalanceInfo"]["balance"]

        return GetBalance(money,money_light,all_balance,useable_balance,points,balance)

    def link_check(self,url:str,web_api:bool=False):
        if "https://" in url:
            url=url.replace("https://pay.paypay.ne.jp/","")

        if web_api:
            headers={
                "Accept":"application/json, text/plain, */*",
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36',
                "Content-Type":"application/json"
            }
            link_info=requests.get(f"https://www.paypay.ne.jp/app/v2/p2p-api/getP2PLinkInfo?verificationCode={url}",headers=headers,proxies=self.proxy).json()
            
        else:
            if not self.access_token:
                raise PayPayLoginError("まずはログインしてください")

            #self.headers=update_header_baggage(self.headers,sentry_public_key,"0.0099999997764826",False,"P2PMoneyTransferDetailFragment",0)
            params={
                "verificationCode": url,
                "payPayLang": "ja"
            }
            link_info=self.session.get("https://app4.paypay.ne.jp/bff/v2/getP2PLinkInfo",headers=self.headers,params=params,proxies=self.proxy).json()
        
        if link_info["header"]["resultCode"] == "S0001":
            raise PayPayLoginError(link_info)
        
        if link_info["header"]["resultCode"] != "S0000":
            raise PayPayError(link_info)
        
        class LinkInfo(NamedTuple):
            sender_name: str
            sender_external_user_id: str
            sender_icon: str
            order_id: str
            chat_room_id: str
            amount: int
            status: str
            money_light: int
            money: int
            has_password: bool
            raw: dict

        sender_name=link_info["payload"]["sender"]["displayName"]
        sender_external_user_id=link_info["payload"]["sender"]["externalId"]
        sender_icon=link_info["payload"]["sender"]["photoUrl"]
        order_id=link_info["payload"]["pendingP2PInfo"]["orderId"]
        chat_room_id=link_info["payload"]["message"]["chatRoomId"]
        amount=link_info["payload"]["pendingP2PInfo"]["amount"]
        status=link_info["payload"]["message"]["data"]["status"]
        money_light=link_info["payload"]["message"]["data"]["subWalletSplit"]["senderPrepaidAmount"]
        money=link_info["payload"]["message"]["data"]["subWalletSplit"]["senderEmoneyAmount"]
        has_password=link_info["payload"]["pendingP2PInfo"]["isSetPasscode"]

        return LinkInfo(sender_name,sender_external_user_id,sender_icon,order_id,chat_room_id,amount,status,money_light,money,has_password,link_info)
    
    def link_receive(self,url:str,passcode:str=None,link_info:dict=None) -> dict:
        if not self.access_token:
            raise PayPayLoginError("まずはログインしてください")

        if "https://" in url:
            url=url.replace("https://pay.paypay.ne.jp/","")

        if not link_info:
            #self.headers=update_header_baggage(self.headers,sentry_public_key,"0.0099999997764826",False,"P2PMoneyTransferDetailFragment",0)
            params={
                "verificationCode": url,
                "payPayLang": "ja"
            }
            link_info=self.session.get("https://app4.paypay.ne.jp/bff/v2/getP2PLinkInfo",headers=self.headers,params=params,proxies=self.proxy).json()
        
        #self.headers=update_header_baggage(self.headers,sentry_public_key)
        payload={
            "requestId":str(uuid4()),
            "orderId":link_info["payload"]["pendingP2PInfo"]["orderId"],
            "verificationCode":url,
            "passcode":None,
            "senderMessageId":link_info["payload"]["message"]["messageId"],
            "senderChannelUrl":link_info["payload"]["message"]["chatRoomId"]
        }
        
        if link_info["header"]["resultCode"] == "S0001":
            raise PayPayLoginError(link_info)
        
        if link_info["header"]["resultCode"] != "S0000":
            raise PayPayError(link_info)
        
        if link_info["payload"]["orderStatus"] != "PENDING":
            raise PayPayError("すでに 受け取り / 辞退 / キャンセル されているリンクです")
        
        if link_info["payload"]["pendingP2PInfo"]["isSetPasscode"] and passcode==None:
            raise PayPayError("このリンクにはパスワードが設定されています")
    
        if link_info["payload"]["pendingP2PInfo"]["isSetPasscode"]:
            payload["passcode"] = passcode
            
        receive = self.session.post("https://app4.paypay.ne.jp/bff/v2/acceptP2PSendMoneyLink",headers=self.headers,json=payload,params={"payPayLang":"ja","appContext":"P2PMoneyTransferDetailScree[...]"},proxies=self.proxy)
        try:
            receive=receive.json()
        except:
            raise PayPayNetWorkError("日本以外からは接続できません")
        
        if receive["header"]["resultCode"] == "S0001":
            raise PayPayLoginError(receive)
        
        if receive["header"]["resultCode"] != "S0000":
            raise PayPayError(receive)
        
        return receive
    
    def link_reject(self,url:str,link_info:dict=None) -> dict:
        if not self.access_token:
            raise PayPayLoginError("まずはログインしてください")

        if "https://" in url:
            url=url.replace("https://pay.paypay.ne.jp/","")

        if not link_info:
            #self.headers=update_header_baggage(self.headers,sentry_public_key,"0.0099999997764826",False,"P2PMoneyTransferDetailFragment",0)
            params={
                "verificationCode": url,
                "payPayLang": "ja"
            }
            link_info=self.session.get("https://app4.paypay.ne.jp/bff/v2/getP2PLinkInfo",headers=self.headers,params=params,proxies=self.proxy).json()
        
        #self.headers=update_header_baggage(self.headers,sentry_public_key)
        payload={
            "requestId":str(uuid4()),
            "orderId":link_info["payload"]["pendingP2PInfo"]["orderId"],
            "verificationCode":url,
            "senderMessageId":link_info["payload"]["message"]["messageId"],
            "senderChannelUrl":link_info["payload"]["message"]["chatRoomId"]
        }
        if link_info["header"]["resultCode"] == "S0001":
            raise PayPayLoginError(link_info)

        if link_info["header"]["resultCode"] != "S0000":
            raise PayPayError(link_info)
        
        if link_info["payload"]["orderStatus"] != "PENDING":
            raise PayPayError("すでに 受け取り / 辞退 / キャンセル されているリンクです")
        
        reject=self.session.post("https://app4.paypay.ne.jp/bff/v2/rejectP2PSendMoneyLink",headers=self.headers,json=payload,params=self.params,proxies=self.proxy).json()
        
        if reject["header"]["resultCode"] == "S0001":
            raise PayPayLoginError(reject)

        if reject["header"]["resultCode"] != "S0000":
            raise PayPayError(reject)
        
        return reject
    
    def link_cancel(self,url:str,link_info:dict=None) -> dict:
        if not self.access_token:
            raise PayPayLoginError("まずはログインしてください")

        if "https://" in url:
            url=url.replace("https://pay.paypay.ne.jp/","")
        if not link_info:
            #self.headers=update_header_baggage(self.headers,sentry_public_key,"0.0099999997764826",False,"P2PMoneyTransferDetailFragment",0)
            params={
                "verificationCode": url,
                "payPayLang": "ja"
            }
            link_info=self.session.get("https://app4.paypay.ne.jp/bff/v2/getP2PLinkInfo",headers=self.headers,params=params,proxies=self.proxy).json()

        #self.headers=update_header_baggage(self.headers,sentry_public_key)
        payload={
            "orderId":link_info["payload"]["pendingP2PInfo"]["orderId"],
            "requestId":str(uuid4()),
            "verificationCode":url,
        }
        if link_info["header"]["resultCode"] == "S0001":
            raise PayPayLoginError(link_info)

        if link_info["header"]["resultCode"] != "S0000":
            raise PayPayError(link_info)
        
        if link_info["payload"]["orderStatus"] != "PENDING":
            raise PayPayError("すでに 受け取り / 辞退 / キャンセル されているリンクです")
        
        cancel=self.session.post("https://app4.paypay.ne.jp/p2p/v1/cancelP2PSendMoneyLink",headers=self.headers,json=payload,params=self.params,proxies=self.proxy).json()
        
        if cancel["header"]["resultCode"] == "S0001":
            raise PayPayLoginError(cancel)
        
        if cancel["header"]["resultCode"] != "S0000":
            raise PayPayError(cancel)
        
        return cancel
    
    def create_link(self,amount:int,passcode:str=None,pochibukuro:bool=False,theme:str="default-sendmoney"):
        if not self.access_token:
            raise PayPayLoginError("まずはログインしてください")

        #self.headers=update_header_baggage(self.headers,sentry_public_key)
        payload={
            "requestId":str(uuid4()),
            "amount":amount,
            "socketConnection": "P2P",
            "theme":theme,
            "source":"sendmoney_home_sns"
        }
        if passcode:
            payload["passcode"]=passcode
        if pochibukuro:
            payload["theme"]="pochibukuro"
        create=self.session.post("https://app4.paypay.ne.jp/bff/v2/executeP2PSendMoneyLink",headers=self.headers,json=payload,params=self.params,proxies=self.proxy)
        try:
            create=create.json()
        except:
            raise PayPayNetWorkError("日本以外からは接続できません")
        
        if create["header"]["resultCode"] == "S0001":
            raise PayPayLoginError(create)
        
        if create["header"]["resultCode"] != "S0000":
            raise PayPayError(create)
        
        class CreateLink(NamedTuple):
            link: str
            chat_room_id: str
            order_id: str
            raw: dict

        link=create["payload"]["link"]
        chat_room_id=create["payload"]["chatRoomId"]
        order_id=create["payload"]["orderId"]
        
        return CreateLink(link,chat_room_id,order_id,create)
    
    def send_money(self,amount:int,receiver_id:str,pochibukuro:bool=False,theme:str="default-sendmoney"):
        if not self.access_token:
            raise PayPayLoginError("まずはログインしてください")

        #self.headers=update_header_baggage(self.headers,sentry_public_key)
        payload = {
            "amount":amount,
            "theme":theme,
            "requestId":str(uuid4()),
            "externalReceiverId":receiver_id,
            "ackRiskError":False,
            "source":"sendmoney_history_chat",
            "socketConnection": "P2P"
        }
        if pochibukuro:
            payload["theme"]="pochibukuro"

        send=self.session.post(f"https://app4.paypay.ne.jp/p2p/v3/executeP2PSendMoney",headers=self.headers,json=payload,params=self.params,proxies=self.proxy)
        try:
            send=send.json()
        except:
            raise PayPayNetWorkError("日本以外からは接続できません")
        
        if send["header"]["resultCode"] == "S0001":
            raise PayPayLoginError(send)
        
        if send["header"]["resultCode"] != "S0000":
            raise PayPayError(send)

        class SendMoney(NamedTuple):
            chat_room_id: str
            order_id: str
            raw: dict
        
        chat_room_id=send["payload"]["chatRoomId"]
        order_id=send["payload"]["orderId"]
        
        return SendMoney(chat_room_id,order_id,send)
    
    def send_message(self,chat_room_id:str,message:str) -> dict:
        if not self.access_token:
            raise PayPayLoginError("まずはログインしてください")

        #if not "sendbird_group_channel_" in chat_room_id:
        #    chat_room_id="sendbird_group_channel_" + chat_room_id
        
        #self.headers=update_header_baggage(self.headers,sentry_public_key)
        payload = {
            "channelUrl":chat_room_id,
            "message":message,
            "socketConnection": "P2P"
        }
        send=self.session.post("https://app4.paypay.ne.jp/p2p/v1/sendP2PMessage",headers=self.headers,json=payload,params=self.params,proxies=self.proxy).json()
        
        if send["header"]["resultCode"] == "S0001":
            raise PayPayLoginError(send)
        
        if send["header"]["resultCode"] != "S0000":
            raise PayPayError(send)
        
        return send
    
    def create_p2pcode(self,amount:int=None):
        if not self.access_token:
            raise PayPayLoginError("まずはログインしてください")
        
        #self.headers=update_header_baggage(self.headers,sentry_public_key)
        payload = {
            "amount":None,
            "sessionId":None
        }
        if amount:
            payload["amount"]=amount
            payload["sessionId"]=str(uuid4())
            
        create_p2pcode=self.session.post("https://app4.paypay.ne.jp/bff/v1/createP2PCode",headers=self.headers,json=payload,params=self.params,proxies=self.proxy).json()
        
        if create_p2pcode["header"]["resultCode"] == "S0001":
            raise PayPayLoginError(create_p2pcode)
        
        if create_p2pcode["header"]["resultCode"] != "S0000":
            raise PayPayError(create_p2pcode)
        
        class P2PCode(NamedTuple):
            p2pcode: str
            raw: dict

        p2pcode=create_p2pcode["payload"]["p2pCode"]

        return P2PCode(p2pcode,create_p2pcode)
    
    def get_profile(self):
        if not self.access_token:
            raise PayPayLoginError("まずはログインしてください")
        
        #self.headers=update_header_baggage(self.headers,sentry_public_key,"0",False,"ProfileFragment",0)
        profile=self.session.get("https://app4.paypay.ne.jp/bff/v2/getProfileDisplayInfo",headers=self.headers,params={"includeExternalProfileSync":"true","completedOptionalTasks": "ENABLED_NEARB[...]"},proxies=self.proxy).json()
        
        if profile["header"]["resultCode"] == "S0001":
            raise PayPayLoginError(profile)

        if profile["header"]["resultCode"] != "S0000":
            raise PayPayError(profile)
        
        class Profile(NamedTuple):
            name: str
            external_user_id: str
            icon: str
            raw: dict

        name=profile["payload"]["userProfile"]["nickName"]
        external_user_id=profile["payload"]["userProfile"]["externalUserId"]
        icon=profile["payload"]["userProfile"]["avatarImageUrl"]

        return Profile(name,external_user_id,icon,profile)

    def set_money_priority(self,paypay_money:bool=False) -> dict:
        if not self.access_token:
            raise PayPayLoginError("まずはログインしてください")

        #self.headers=update_header_baggage(self.headers,sentry_public_key)

        if paypay_money:
            setting={"moneyPriority":"MONEY_FIRST"}
        else:
            setting={"moneyPriority":"MONEY_LITE_FIRST"}

        smp=self.session.post("https://app4.paypay.ne.jp/p2p/v1/setMoneyPriority",headers=self.headers,json=setting,params={"payPayLang":"ja"},proxies=self.proxy).json()
        
        if smp["header"]["resultCode"] == "S0001":
            raise PayPayLoginError(smp)
        
        if smp["header"]["resultCode"] != "S0000":
            raise PayPayError(smp)

        return smp
    
    def get_chat_rooms(self,size:int=20,last_message:bool=True):
        if not self.access_token:
            raise PayPayLoginError("まずはログインしてください")
        
        #self.headers=update_header_baggage(self.headers,sentry_public_key,"0.0099999997764826",False,"P2PChatRoomListFragment",0)
        params={
            "pageSize":str(size),
            "customTypes":"P2P_CHAT,P2P_CHAT_INACTIVE,P2P_PUBLIC_GROUP_CHAT,P2P_LINK,P2P_OLD",
            "requiresLastMessage":last_message,
            "socketConnection": "P2P",
            "payPayLang":"ja"
        }
        getchat=self.session.get("https://app4.paypay.ne.jp/p2p/v1/getP2PChatRoomListLite",headers=self.headers,params=params,proxies=self.proxy).json()
        
        if getchat["header"]["resultCode"] == "S0001":
            raise PayPayLoginError(getchat)
        
        if getchat["header"]["resultCode"] == "S5000":
            raise PayPayError("チャットルームが見つかりませんでした")
 
        if getchat["header"]["resultCode"] != "S0000":
            raise PayPayError(getchat)

        return getchat
    
    def get_chat_room_messages(self,chat_room_id:str,prev:int=15,next:int=0,include:bool=False) -> dict:
        if not self.access_token:
            raise PayPayLoginError("まずはログインしてください")
        
        if not "sendbird_group_channel_" in chat_room_id:
            chat_room_id="sendbird_group_channel_" + chat_room_id

        #self.headers=update_header_baggage(self.headers,sentry_public_key,"0.0099999997764826",False,"P2PChatRoomFragment",0)
        params={
            "chatRoomId":chat_room_id,
            "include":include,
            "prev":str(prev),
            "next":str(next),
            "payPayLang":"ja"
        }
        getchat=self.session.get("https://app4.paypay.ne.jp/bff/v1/getP2PMessageList",headers=self.headers,params=params,proxies=self.proxy).json()
        
        if getchat["header"]["resultCode"] == "S0001":
            raise PayPayLoginError(getchat)
        
        if getchat["header"]["resultCode"] == "S5000":
            raise PayPayError("チャットルームが見つかりませんでした")
 
        if getchat["header"]["resultCode"] != "S0000":
            raise PayPayError(getchat)

        return getchat
    
    def get_point_history(self) -> dict:
        if not self.access_token:
            raise PayPayLoginError("まずはログインしてください")

        #self.headers=update_header_baggage(self.headers,sentry_public_key)
        params = {
            "pageSize": "20",
            "orderTypes": "CASHBACK",
            "paymentMethodTypes": "",
            "signUpCompletedAt": "2021-01-02T10:16:24Z",
            "pointType": "REGULAR",
            "isOverdraftOnly": "false",
            "payPayLang": "ja"
        }
        phistory = self.session.get("https://app4.paypay.ne.jp/bff/v3/getPaymentHistory",headers=self.headers,params=params,proxies=self.proxy).json()
        
        if phistory["header"]["resultCode"] == "S0001":
            raise PayPayLoginError(phistory)

        if phistory["header"]["resultCode"] != "S0000":
            raise PayPayError(phistory)
        
        return phistory
    
    def search_p2puser(self,user_id:str,size:int=10,is_global:bool=True,order:int=0):
        if not self.access_token:
            raise PayPayLoginError("まずはログインしてください")

        #self.headers=update_header_baggage(self.headers,sentry_public_key)
        payload={
            "searchTerm":user_id,
            "pageToken":"",
            "pageSize":size,
            "isIngressSendMoney":False,
            "searchTypes":"GLOBAL_SEARCH"
        }
        if not is_global:
            payload["searchTypes"]="FRIEND_AND_CANDIDATE_SEARCH"

        p2puser = self.session.post("https://app4.paypay.ne.jp/p2p/v3/searchP2PUser",headers=self.headers,json=payload,params=self.params,proxies=self.proxy).json()
        if p2puser["header"]["resultCode"] == "S0001":
            raise PayPayLoginError(p2puser)

        if p2puser["header"]["resultCode"] != "S0000":
            if p2puser["error"]["displayErrorResponse"]["description"]=="しばらく時間をおいて、再度お試しください":
                raise PayPayError("レート制限に達しました")
            
            raise PayPayError(p2puser)
        
        if p2puser["payload"]["searchResultEnum"] == "NO_USERS_FOUND":
            raise PayPayError("ユーザーが見つかりませんでした")

        class P2PUser(NamedTuple):
            name: str
            icon: str
            external_user_id: str
            raw: dict

        if is_global:
            name=p2puser["payload"]["globalSearchResult"]["displayName"]
            icon=p2puser["payload"]["globalSearchResult"]["photoUrl"]
            external_user_id=p2puser["payload"]["globalSearchResult"]["externalId"]
        else:
            name=p2puser["payload"]["friendsAndCandidatesSearchResults"]["friends"][order]["displayName"]
            icon=p2puser["payload"]["friendsAndCandidatesSearchResults"]["friends"][order]["photoUrl"]
            external_user_id=p2puser["payload"]["friendsAndCandidatesSearchResults"]["friends"][order]["externalId"]
        
        return P2PUser(name,icon,external_user_id,p2puser)
    
    def initialize_chatroom(self,external_user_id:str):
        if not self.access_token:
            raise PayPayLoginError("まずはログインしてください")
        
        #self.headers=update_header_baggage(self.headers,sentry_public_key,"0.0099999997764826",False,"P2PChatRoomFragment",0)
        payload={
            "returnChatRoom":True,
            "shouldCheckMessageForFriendshipAppeal":True,
            "externalUserId":external_user_id,
            "socketConnection": "P2P"
        }
        initialize = self.session.post("https://app4.paypay.ne.jp/p2p/v1/initialiseOneToOneAndLinkChatRoom",headers=self.headers,json=payload,params=self.params,proxies=self.proxy).json()
        if initialize["header"]["resultCode"] == "S0001":
            raise PayPayLoginError(initialize)

        if initialize["header"]["resultCode"] == "S5000":
            raise PayPayError("チャットルームが見つかりませんでした")

        if initialize["header"]["resultCode"] != "S0000":
            raise PayPayError(initialize)

        class InitializeChatRoom(NamedTuple):
            chatroom_id: str
            raw: dict

        chatroom_id=initialize["payload"]["chatRoom"]["chatRoomId"]

        return InitializeChatRoom(chatroom_id,initialize)
    
    def get_barcode_info(self, url: str):
        if not self.access_token:
            raise PayPayLoginError("まずはログインしてください")
        
        params = {
            "code": url,
            # "paymentMethodId": "135062845",
            # "paymentMethodType": "PAY_LATER_CC",
            # "lastSelectedHomePaymentMethodId": "135062845",
            # "lastSelectedHomePaymentMethodType": "PAY_LATER_CC",
            "payPayLang": "ja"
        }
        barcode=self.session.get("https://app4.paypay.ne.jp/bff/v2/getBarcodeInfo",headers=self.headers,params=params,proxies=self.proxy).json()

        if barcode["header"]["resultCode"] == "S0001":
            raise PayPayLoginError(barcode)

        if barcode["header"]["resultCode"] != "S0000":
            raise PayPayError(barcode)
        
        class BarcodeInfo(NamedTuple):
            amount: int
            user_name: str
            external_user_id: str
            user_icon: str
            raw: dict

        return BarcodeInfo(
            amount=barcode["payload"]["userCodeInfo"]["amount"],
            user_name=barcode["payload"]["userCodeInfo"]["userInfo"]["displayName"],
            external_user_id=barcode["payload"]["userCodeInfo"]["userInfo"]["externalUserId"],
            user_icon=barcode["payload"]["userCodeInfo"]["userInfo"]["avatarImageUrl"],
            raw=barcode
        )
        
    def alive(self) -> None:
        if not self.access_token:
            raise PayPayLoginError("まずはログインしてください")
        
        #self.headers=update_header_baggage(self.headers,sentry_public_key,"0.0099999997764826",False,"MainActivity",0)
        alive=self.session.get("https://app4.paypay.ne.jp/bff/v1/getGlobalServiceStatus?payPayLang=en",headers=self.headers,proxies=self.proxy).json()
        if alive["header"]["resultCode"] == "S0001":
            raise PayPayLoginError(alive)
        
        if alive["header"]["resultCode"] != "S0000":
            raise PayPayError(alive)
        
        self.session.post("https://app4.paypay.ne.jp/bff/v3/getHomeDisplayInfo?payPayLang=ja",headers=self.headers,json={"excludeMissionBannerInfoFlag": False,"includeBeginnerFlag": False,"includeSkinInfoFlag": False,"networkStatus": "WIFI"},proxies=self.proxy)
        self.session.get("https://app4.paypay.ne.jp/bff/v1/getSearchBar?payPayLang=ja",headers=self.headers,proxies=self.proxy)
