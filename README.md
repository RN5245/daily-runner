# daily-runner

公开仓库（Actions 免费用、无限分钟），用来跑每日定时任务。

## 运行说明
- **每天 3 次**：北京时间 09:17 / 16:43 / 22:05
- 每次再随机延后 0~10 分钟（避开整点洪峰）
- 也可在 Actions 页点 `Run workflow` 手动触发，并临时传 `url` / `jitter`

## 配置要访问的地址
在仓库 **Settings → Secrets and variables → Actions → New repository secret** 添加：
- `TARGET_URL`：**必填**，要访问的网址（如 `https://example.com/api/ping`）
- `EXTRA_TOKEN`：可选，URL 需要的 token（脚本里作为环境变量读取，不会出现在公开代码）

> ⚠️ 仓库是 public，所有代码和 Actions 日志对全网可见。
> 但 Secrets 永不显示明文——只要不要把密钥写进脚本或 `echo` 出来，就安全。

## 改触发时间
编辑 `.github/workflows/daily.yml` 里的 `schedule` 段。cron 为 **UTC**：
```
分钟 小时 日 月 周
```
北京时间 = UTC + 8（例如北京 09:00 = UTC 01:00，写 `0 1 * * *`）。

常用档：
- 每小时：`0 * * * *`
- 每天 08:00 北京：`0 0 * * *`
- 每 6 小时：`0 */6 * * *`
