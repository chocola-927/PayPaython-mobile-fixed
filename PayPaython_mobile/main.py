import requests
from uuid import uuid4
import pkce
import random
from typing import NamedTuple, Optional
import time
import os

# aws waf 突破ヘルパーを追加
from .waf_helper import solve_aws_waf

# デバッグ制御: 環境変数 PAYPAY_SKIP_WAF=1 で WAF チェックをスキップ
SKIP_WAF = os.getenv("PAYPAY_SKIP_WAF", "0") == "1"

'''def generate_sentry():
    trace_id = uuid4().hex
    span_id = uuid4().hex[16:]

    class SENTRY_TRACE_SPAN(NamedTuple):
        trace_id:str
        span_id:str
        sentry_trace:str
        sentry_trace_0:str
        sentry_trace_1:str
    
    return SENTRY_TRACE_SPAN(trace_id, span_id, f"{trace_id}-{span_id}", f"{trace_id}-{span_id}-0", f"{trace_id}-{span_id}-1")'''  


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


def update_header_device_state(headers:dict):
    device_state = generate_device_state()
    headers["Device-Orientation"] = device_state.device_orientation
    headers["Device-Orientation-2"] = device_state.device_orientation_2
    headers["Device-Rotation"] = device_state.device_rotation
    headers["Device-Rotation-2"] = device_state.device_rotation_2
    headers["Device-Acceleration"] = device_state.device_acceleration
    headers["Device-Acceleration-2"] = device_state.device_acceleration_2

    return headers

'''sentry_public_key="e5f3c063d55d3058bc5bfb0f311152e4"
def update_header_baggage(header:dict,public_key:str,sample_rate:str=None,sampled:bool=None,transaction:str=None,sentry_trace_style:int=None):
    baggage = "sentey-environment=Production," + f"sentry-public_key={public_key},sentry-release=consumer-android%404.78.1%2B47801"
    if sample_rate:
        baggage = baggage + f",sentry-sample_rate={sample_rate}"

    if sampled!=None:
        if sampled:
            baggage = baggage + ",sentry-sampled=true"
        else:
            baggage = baggage + ",sentry-sampled=false"

    #sentry_ids = generate_sentry()
    baggage = baggage + f",sentry-trace_id={sentry_ids.trace_id}"

    if transaction:
        baggage = baggage + f",sentry-transaction={transaction}"

    if sentry_trace_style == 0:
        header[#"sentry-trace"] = sentry_ids.sentry_trace_0
    elif sentry_trace_style == 1:
        header[#"sentry-trace"] = sentry_ids.sentry_trace_1
    else:
        header[#"sentry-trace"] = sentry_ids.sentry_trace
    
    header[#"baggage"] = baggage
    return header'''  


class PayPayError(Exception):
    pass
class PayPayLoginError(Exception):
    pass
class PayPayNetWorkError(Exception):
    pass
class PayPay():
    def __init__(self,phone:str=None,password:str=None,device_uuid:str=None,client_uuid:str=str(uuid4()),access_token:str=None,proxy=None):
        
        if phone and "-" in phone:
            phone=phone.replace("-","")

        self.session=requests.Session()

        if device_uuid:
            self.device_uuid=device_uuid
        else:
            self.device_uuid=str(uuid4())
            
        self.client_uuid=client_uuid

        if isinstance(proxy, str):
            if not "http" in proxy:
                proxy = "http://" + proxy
            self.proxy={"https":proxy,"http":proxy}

        elif isinstance(proxy, dict):
            self.proxy=proxy
            
        else:
            self.proxy=proxy

        self.params={
            "payPayLang":"ja"
        }
        #try:
        #    iosstore=self.session.get("https://apps.apple.com/jp/app/paypay-%E3%83%9A%E3%82%A4%E3%83%9A%E3%82%A4/id1435783608",proxies=self.proxy)
        #except Exception as e:
        #    raise NetWorkError(e)
        
        self.version="5.11.1" #BeautifulSoup(iosstore.text,"html.parser").find(class_="l-column small-6 medium-12 whats-new__latest__version").text.split()[1]
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
            self.access_token=access_token
            self.headers["Authorization"]=f"Bearer {self.access_token}"
            self.headers["content-type"]="application/json"

        elif phone:
            self.access_token=None
            self.refresh_token=None
            self.code_verifier, self.code_challenge = pkce.generate_pkce_pair(43)
            ##self.headers=update_header_baggage(self.headers,sentry_public_key,"0",False,"OAuth2Fragment",0)

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
            par=self.session.post("https://app4.paypay.ne.jp/bff/v2/oauth2/par?payPayLang=ja",headers=self.headers,data=payload,proxies=self.proxy)
            try:
                par=par.json()
            except:
                raise PayPayNetWorkError("日本以外からは接続できません")
            
            if par["header"]["resultCode"] != "S0000":
                raise PayPayLoginError(par)
            
            headers = {
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "Accept-Encoding": "gzip, deflate, br, zstd",
                "Accept-Language": "ja-JP,ja;q=0.9",
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "Host": "www.paypay.ne.jp",
                "is-emulator": "false",
                "Pragma": "no-cache",
                "sec-ch-ua": '"Not A(Brand";v="8", "Chromium";v="132", "Android WebView";v="132"',
                "sec-ch-ua-mobile": "?1",
                "sec-ch-ua-platform": '"Android"',
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
                "Upgrade-Insecure-Requests": "1",
                "User-Agent": f"Mozilla/5.0 (Linux; Android 10; SCV38 Build/QP1A.190711.020; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/132.0.6834.163 Mobile Safari/537.36 jp.p[...]",
                "X-Requested-With": "jp.ne.paypay.android.app"
            }
            params = {
                "client_id": "pay2-mobile-app-client",
                "request_uri": par["payload"]["requestUri"]
            }

            def try_solve_waf(retries: int = 2, wait: float = 0.5) -> Optional[str]:
                if SKIP_WAF:
                    return None
                last_exc = None
                for i in range(retries):
                    try:
                        token = solve_aws_waf(self.session,
                                             check_url="https://www.paypay.ne.jp/portal/oauth2/sign-in",
                                             domain="www.paypay.ne.jp",
                                             user_agent=self.headers.get("User-Agent"),
                                             proxy=self.proxy,
                                             timeout=30)
                        if token:
                            return token
                    except Exception as e:
                        last_exc = e
                    time.sleep(wait)
                # 最終的には None を返す
                return None

            # authorize 呼び出し前に WAF を試す
            try:
                try_solve_waf()
            except Exception:
                pass

            # オーソライズ呼び出し
            self.session.get(f"https://www.paypay.ne.jp/portal/api/v2/oauth2/authorize",headers=headers,params=params,proxies=self.proxy)

            # sign-in ページにアクセスする直前にも念のため WAF 突破を試みる
            try:
                try_solve_waf()
            except Exception:
                pass

            params = {
                "client_id": "pay2-mobile-app-client",
                "mode": "landing"
            }
            self.session.get("https://www.paypay.ne.jp/portal/oauth2/sign-in",headers=headers,params=params,proxies=self.proxy)
            
            #sentry_ids = generate_sentry()
            headers = {
                "Accept": "application/json, text/plain, */*",
                "Accept-Encoding": "gzip, deflate, br, zstd",
                "Accept-Language": "ja-JP,ja;q=0.9",
                #"baggage": f"sentry-environment=Production,sentry-release=4.75.0,sentry-public_key=a5e3ae80a20e15b8de50274dd231ab83,sentry-trace_id={sentry_ids.trace_id},sentry-sample_rate=0.000[...]",
                "Cache-Control": "no-cache",
                "Client-Id": "pay2-mobile-app-client",
                "Client-Type": "PAYPAYAPP",
                "Connection": "keep-alive",
                "Host": "www.paypay.ne.jp",
                "Pragma": "no-cache",
                "Referer": "https://www.paypay.ne.jp/portal/oauth2/sign-in?client_id=pay2-mobile-app-client&mode=landing",
                "sec-ch-ua": '"Not A(Brand";v="8", "Chromium";v="132", "Android WebView";v="132")',
                "sec-ch-ua-mobile": "?1",
                "sec-ch-ua-platform": '"Android"',
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
                #"sentry-trace": sentry_ids.sentry_trace_0,
                "User-Agent": f"Mozilla/5.0 (Linux; Android 10; SCV38 Build/QP1A.190711.020; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/132.0.6834.163 Mobile Safari/537.36 jp.p[...]",
                "X-Requested-With": "jp.ne.paypay.android.app"
            }
            par_check=self.session.get("https://www.paypay.ne.jp/portal/api/v2/oauth2/par/check",headers=headers,proxies=self.proxy).json()
            if par_check["header"]["resultCode"] != "S0000":
                raise PayPayLoginError(par_check)
            
            #sentry_ids = generate_sentry()
            headers = {
                "Accept": "application/json, text/plain, */*",
                "Accept-Encoding": "gzip, deflate, br, zstd",
                "Accept-Language": "ja-JP,ja;q=0.9",
                #"baggage": f"sentry-environment=Production,sentry-release=4.75.0,sentry-public_key=a5e3ae80a20e15b8de50274dd231ab83,sentry-trace_id={sentry_ids.trace_id}",
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
                "Referer": "https://www.paypay.ne.jp/portal/oauth2/sign-in?client_id=pay2-mobile-app-client&mode=landing",
                "sec-ch-ua": '"Not A(Brand";v="8", "Chromium";v="132", "Android WebView";v="132")',
                "sec-ch-ua-mobile": "?1",
                "sec-ch-ua-platform": '"Android"',
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
                #"sentry-trace": sentry_ids.sentry_trace,
                "User-Agent": f"Mozilla/5.0 (Linux; Android 10; SCV38 Build/QP1A.190711.020; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/132.0.6834.163 Mobile Safari/537.36 jp.p[...]",
                "X-Requested-With": "jp.ne.paypay.android.app"
            }
            payload={
                "username":phone,
                "password":password,
                "signInAttemptCount":1
            }
            signin=self.session.post("https://www.paypay.ne.jp/portal/api/v2/oauth2/sign-in/password",headers=headers,json=payload,proxies=self.proxy).json()
            if signin["header"]["resultCode"] != "S0000":
                raise PayPayLoginError(signin)
            
            if device_uuid:
                try:
                    uri=signin["payload"]["redirectUrl"].replace("paypay://oauth2/callback?","").split("&")
                except:
                    raise PayPayLoginError("登録されていないDevice-UUID")
                
                headers = self.headers
                del headers["Device-Lock-Type"]
                del headers["Device-Lock-App-Setting"]
                #del headers["baggage"]
                #del headers["sentry-trace"]
                
                confirm_data={
                    "clientId":"pay2-mobile-app-client",
                    "redirectUri":"paypay://oauth2/callback",
                    "code":uri[0].replace("code=",""),
                    "codeVerifier":self.code_verifier
                }
                get_token=self.session.post("https://app4.paypay.ne.jp/bff/v2/oauth2/token",headers=headers,data=confirm_data,params=self.params,proxies=self.proxy).json()
                if get_token["header"]["resultCode"] != "S0000":
                    raise PayPayLoginError(get_token)
                
                self.access_token=get_token["payload"]["accessToken"]
                self.refresh_token=get_token["payload"]["refreshToken"]
                self.headers["Authorization"]=f"Bearer {self.access_token}"
                self.headers["content-type"]="application/json"
                self.headers=update_header_device_state(self.headers)

            else:
                code_update=self.session.post("https://www.paypay.ne.jp/portal/api/v2/oauth2/extension/code-grant/update",headers=headers,json={},proxies=self.proxy).json()
                if code_update["header"]["resultCode"] != "S0000":
                    raise PayPayLoginError(code_update)
                
                headers["Referer"]="https://www.paypay.ne.jp/portal/oauth2/verification-method?client_id=pay2-mobile-app-client&mode=navigation-2fa"
                payload={
                    "params":{
                        "extension_id":"user-main-2fa-v1",
                        "data":{
                            "type":"SELECT_FLOW",
                            "payload":{
                                "flow":"OTL",
                                "sign_in_method":"MOBILE",
                                "base_url":"https://www.paypay.ne.jp/portal/oauth2/l"
                                }
                            }
                        }
                    }
                
                nav_2fa=self.session.post("https://www.paypay.ne.jp/portal/api/v2/oauth2/extension/code-grant/update",headers=headers,json=payload,proxies=self.proxy).json()
                if nav_2fa["header"]["resultCode"] != "S0000":
                    raise PayPayLoginError(nav_2fa)
                
                headers["Referer"]="https://www.paypay.ne.jp/portal/oauth2/otl-request?client_id=pay2-mobile-app-client&mode=navigation-2fa"
                otl_request=self.session.post("https://www.paypay.ne.jp/portal/api/v2/oauth2/extension/code-grant/side-channel/next-action-polling",headers=headers,json={"waitUntil": "PT5S"},prox[...]