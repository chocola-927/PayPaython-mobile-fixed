import sys
import os
import json
import functools
import datetime
from pathlib import Path

# 環境変数で簡易デバッグ表示を有効化（既存の _debug も使われます）
os.environ.setdefault("PAYPAY_DEBUG", "1")

# import モジュール（リポジトリのパッケージ構成によってはパス調整が必要）
try:
    from PayPaython_mobile.main import PayPay, PayPayLoginError, PayPayNetWorkError, PayPayError
except Exception as e:
    print("モジュールの import に失敗しました:", e)
    print("このスクリプトはリポジトリのルートから実行してください（例: PYTHONPATH=. python PayPaython_mobile/debug_login_sms.py ...）")
    raise

def make_logger(out_dir="paypay_debug_logs"):
    out = Path(out_dir)
    out.mkdir(exist_ok=True)
    counter = {"n": 0}
    def log(method, url, req_kwargs, resp):
        counter["n"] += 1
        idx = counter["n"]
        ts = datetime.datetime.utcnow().isoformat() + "Z"
        filename = out / f"{idx:03d}_{method}_{Path(url).name}.log"
        try:
            rbody = resp.text
        except Exception:
            rbody = "<no-text>"
        data = {
            "time": ts,
            "method": method,
            "url": url,
            "request": {
                "headers": {k:v for k,v in (req_kwargs.get("headers") or {}).items()},
                "params": req_kwargs.get("params"),
                "data": req_kwargs.get("data"),
                "json": req_kwargs.get("json")
            },
            "response": {
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "text": rbody
            }
        }
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"[debug] logged {filename}")
    return log

def wrap_session_requests(session, logger):
    orig = session.request
    def wrapped(method, url, **kwargs):
        print(f"[http] {method.upper()} {url}")
        # short display of outgoing headers / params
        if "headers" in kwargs:
            print("  -> headers:", {k:kwargs["headers"].get(k) for k in ["User-Agent","Referer","Origin","X-Requested-With"] if k in kwargs["headers"]})
        if "params" in kwargs:
            print("  -> params:", kwargs["params"])
        if "json" in kwargs:
            print("  -> json payload keys:", list(kwargs["json"].keys())[:10])
        resp = orig(method, url, **kwargs)
        print(f"  <- {resp.status_code} {resp.reason} (len={len(resp.content)})")
        try:
            # try parse json for quick glance
            j = resp.json()
            print("  <- json header.resultCode:", j.get("header", {}).get("resultCode"))
        except Exception:
            pass
        try:
            logger(method.upper(), url, kwargs, resp)
        except Exception as e:
            print("logger error:", e)
        return resp
    session.request = wrapped

def main():
    if len(sys.argv) < 3:
        print("使い方: python PayPaython_mobile/debug_login_sms.py <phone> <password> [--proxy http://..]")
        sys.exit(1)
    phone = sys.argv[1]
    password = sys.argv[2]
    proxy = None
    if len(sys.argv) >= 5 and sys.argv[3] == "--proxy":
        proxy = sys.argv[4]
    logger = make_logger()
    client = PayPay(phone=phone, password=password, device_uuid=None, proxy=proxy)
    # ラップして全てログを取る
    wrap_session_requests(client.session, logger)
    try:
        client.prepare_login_flow_with_waf(phone=phone, password=password, device_uuid=None)
        print("prepare_login_flow_with_waf() finished. SMS should have been requested (check logs/paypay_debug_logs).")
    except PayPayLoginError as e:
        print("PayPayLoginError:", e)
    except PayPayNetWorkError as e:
        print("PayPayNetWorkError:", e)
    except PayPayError as e:
        print("PayPayError:", e)
    except Exception as e:
        print("Unexpected error:", e)

if __name__ == "__main__":
    main()
