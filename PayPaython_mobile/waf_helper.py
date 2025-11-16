from typing import Optional
import time

try:
    from awswaf.aws import AwsWaf
except Exception as e:
    raise RuntimeError("awswaf が import できません。") from e

def solve_aws_waf(session, check_url: str = "https://www.paypay.ne.jp/",
                  domain: str = "www.paypay.ne.jp",
                  user_agent: Optional[str] = None,
                  proxy: Optional[dict] = None,
                  timeout: int = 30) -> Optional[str]:

    ua = user_agent or session.headers.get("User-Agent", "Mozilla/5.0")
    headers = {"User-Agent": ua, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}

    try:
        resp = session.get(check_url, headers=headers, proxies=proxy, timeout=timeout)
    except Exception as e:
        raise

    html = getattr(resp, "text", "") or ""
    # awswaf.extract は "window.gokuProps = " を想定しているので、その存在で判定
    if "window.gokuProps" not in html:
        return None

    # extract して AwsWaf を動かす
    try:
        goku_props, host = AwsWaf.extract(html)
        aw = AwsWaf(goku_props, host, domain, user_agent=ua)
        token = aw()  # トークンを取得
    except Exception:
        return None

    # セッションに cookie と headers の cookie を注入
    cookie_name = "aws-waf-token"
    # set cookie for both .domain and host-specific domain
    session.cookies.set(cookie_name, token, domain="." + domain, path="/")
    session.cookies.set(cookie_name, token, domain=domain, path="/")
    # headers の cookie にも追加（既存があれば保持）
    prev_cookie = session.headers.get("cookie", "")
    new_cookie = (prev_cookie + ("; " if prev_cookie else "") + f"{cookie_name}={token}")
    session.headers["cookie"] = new_cookie

    # 少し待機して戻す
    time.sleep(0.2)
    return token
