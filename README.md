# zjmf-v1-register-unauth-account-poc

魔方财务v3.8.0及以下客户区OpenAPI`POST /v1/register`空参数未授权注册漏洞的PoC。空请求可创建无邮箱、无手机号、无密码的客户账号，并返回可用JWT。

仅限授权安全测试。默认不创建账号，必须显式传入`--i-have-permission`。

## 环境

Python 3.8+，无第三方依赖。

## 使用

只读检查：

```bash
python3 poc.py --host https://your-zjmf-host --check
```

单账号验证：

```bash
python3 poc.py --host https://your-zjmf-host --i-have-permission
```

## 参数

| 参数 | 说明 |
| --- | --- |
| `--host` | 目标地址，必填 |
| `--check` | 只读检查，不创建账号 |
| `--i-have-permission` | 确认已获授权，允许创建单账号 |
| `--timeout` | HTTP超时秒数，默认10 |
| `--insecure` | 跳过TLS证书校验 |
| `--verbose` | 打印完整响应体 |

## 影响

未登录访问者可创建账号，绕过邮箱、手机验证与验证码；账号可获得JWT并调用客户区OpenAPI，且不产生注册日志。

## 修复建议

1. 入口强制要求手机号或邮箱，并校验验证码与限流。
2. `ClientsModel::register()`在邮箱和手机号同时为空时拒绝注册。
3. 不要给未验证身份的账号签发正常登录JWT。
4. 无论邮箱或手机是否为空都写注册日志。

测试结束后在后台或数据库删除创建的空账号。

## License

MIT，见`LICENSE`。
