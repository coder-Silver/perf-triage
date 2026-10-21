# 性能初筛（第一版）

本机网页工具。把已经抓好的日志目录交给它，按规则标出有问题的进程和等级。不填 API Key 也能分析。目录里有 `.pftrace` 时，可以打开 Perfetto 时间线，并只对实际抓到的方向给出初步结论。

只监听本机 `http://127.0.0.1:8765`。API Key 保存在本机用户目录的 `.perf-triage/config.json`，页面不回显。

## Windows 一键部署

安装包里已经带好 Python 和调度分析组件，不需要再下载。

1. 保持 `一键安装.bat` 和 `vendor` 文件夹在同一目录。
2. 双击 `一键安装.bat`。
3. 浏览器打开 `http://127.0.0.1:8765`。

也可以双击桌面上的「性能初筛」快捷方式。它会指向同一个安装入口。

如果提示缺少 `vendor\python\python.exe` 或 `vendor\trace_processor_shell.exe`，说明安装包不完整，需要重新拷贝整个目录，而不是只拷贝 bat 文件。

## Mac 一键部署

1. 若系统还没有 Python，先安装 Python 3.11 或更新版本：<https://www.python.org/downloads/macos/>。
2. 在终端进入本目录，执行一次：

   ```bash
   chmod +x 一键安装.command
   ```

3. 之后双击 `一键安装.command`。终端会留下窗口，浏览器打开 `http://127.0.0.1:8765`。

第一次启动需要网络：脚本会在 `vendor/mac-venv` 安装 Python 依赖，并按芯片下载 Perfetto v57.2 的 `trace_processor_shell`（Apple 芯片或 Intel）。下载后会校验 SHA256。以后再双击不再下载。

如果双击没有反应，在终端执行：

```bash
bash 一键安装.command
```

选目录时使用系统的文件夹对话框，会出现在最前面。取消只关闭对话框，不会开始分析。

## 使用

1. 打开页面后，可以先选模型。地址会随模型填好。API Key 可以后填；不填时，等级和进程仍由规则给出。
2. 点「浏览…」选择日志目录，或把路径粘贴进输入框。选完不会自动分析。
3. 点「开始分析」。按钮下方会显示「正在读取日志并定级」。
4. 结论栏只列出达到 P0 / P1 / P2 的进程。可以在结论下面继续提问。
5. 这次目录里有 trace 时，结论栏会出现「查看 trace 分析」。分析一结束就会在后台加载 Perfetto。点开后，左侧是有数据的方向结论，右侧是时间线。返回主页仍显示刚才的结论。

支持的输入：

- 文本日志：logcat、bugreport、tombstone，以及内容能识别成这些日志的文件。
- 压缩包：`.zip`、`.gz`，会自动解压后再识别。
- Trace：`.pftrace`、`.perfetto-trace`、`.ptrace`。

没有抓到某一方向的数据时，Trace 页不分析那个方向。例如没有帧时间线或掉帧日志，就不给出显示帧率结论。

## 等级

| 等级 | 含义 |
| --- | --- |
| P0 | 分析窗口内的 ANR、Watchdog、system_server 卡顿或系统进程崩溃 |
| P1 | 进程崩溃、异常刷屏、连续掉帧、主线程调度异常，以及达到阈值的 CPU 占用 |
| P2 | 限频、内存压力，以及较低阈值的 CPU 占用 |

Trace 页还会对「有数据但未达到等级」的方向写一句初步结论。

## 模型和 Key

页面只需要三项：模型、自动带出的 API 地址、API Key。Key 按服务地址分开保存。保存时会测试能否连通，并显示耗时。密钥不会出现在页面和结论文件里。

没有 Key 时可以分析、查看 trace、按规则继续提问。配置 Key 后，模型只解释已经定级的证据。

## 文件位置

| 内容 | 位置 |
| --- | --- |
| 页面和规则 | 本目录 |
| Windows 运行时 | `vendor/python`、`vendor/trace_processor_shell.exe` |
| Mac 运行时 | `vendor/mac-venv`、`vendor/trace_processor_shell` |
| 配置和 Key | 用户主目录 `.perf-triage/config.json` |
| 上次结论 | 用户主目录 `.perf-triage/trace-cache/report.json` |

## 常见问题

- 页面打不开：确认终端里的一键安装还在运行，地址是 `http://127.0.0.1:8765`。
- 再双击一次：如果本机已经开着本工具，会先关掉旧进程再启动。
- Mac 提示没有 python3：先安装 Python，再双击。
- Trace 时间线空白：第一次打开 Perfetto 界面需要能访问 `https://ui.perfetto.dev`。分析结束后会在后台开始加载，点「查看 trace 分析」时如果还在下载，等它进入时间线即可。
- 只有 bugreport、没有 `.pftrace`：可以做日志定级，不会出现可点的「查看 trace 分析」。

## 许可证

本项目代码采用 [MIT License](LICENSE)。

`vendor/` 下的第三方组件遵循各自许可证：

- `vendor/python`：Python Software Foundation License，见 `vendor/python/LICENSE.txt`
- `vendor/trace_processor_shell.exe`：Perfetto，Apache License 2.0

