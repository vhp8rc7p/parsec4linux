# parsec4linux

非官方的 **Parsec Linux 被控端（host）**，个人自用。

*[English](README.md)*

Parsec 官方只提供 Linux *客户端*，没有 Linux *被控端*：你可以**从** Linux 连出去，但不能连
**到** Linux。这个项目补上缺失的被控端，让一台 Linux 机器可以成为被远程控制的那一方。

**状态：可用。** 真实的 Parsec 客户端能连上来，流畅地显示 Linux 桌面画面，并且能操作它的
鼠标和键盘。

## 测试环境

只在下面这一套环境上验证过，其余情况都请视为未验证：

| | |
|---|---|
| 被控端系统 | Ubuntu 24.04.2 LTS，内核 6.17.0-23-generic |
| 显示服务 | **Wayland**（GNOME Shell 46.0），不是 X11；抓屏走 portal，输入走 `uinput`，因为这里 XTEST 不可用 |
| 硬件 | VMware 虚拟机，纯软件编码（没有 GPU 编码器） |
| 桌面分辨率 | 随虚拟机窗口可变；见过 1482×537 和 2554×1367。高度是奇数，这就是编码尺寸要向下取偶的原因——否则 x264 根本起不来。 |
| Python | 3.12.3 |
| GStreamer | 1.24.2，x264enc 1.24.1 |
| PipeWire / portal | libpipewire 1.0.5，xdg-desktop-portal 1.18.4 |
| 客户端 | Windows 10 上的官方 Parsec 客户端，1920×1080 |
| Parsec 引擎版本 | `150-105c` |

代码里没有任何依赖 X11 的地方，但也从没在 X11 上**跑过**。Arch、其他发行版、以及非 GNOME 的
Wayland 合成器理论上都能用：抓屏只需要 ScreenCast portal，输入只需要 `/dev/uinput`。未验证。

## 已经实现

- kessel REST 登录与 WebSocket 信令；被控端会出现在客户端的机器列表里
- ICE/STUN 连通性、NAT 候选地址交换
- BUD 传输层：AES-256-GCM、可靠分片（MTU 1193）、累积确认与单条消息确认、实测 RTT、
  按 Parsec 自己的 RTO 曲线重传、100 个分片的拥塞窗口
- 客户端状态栏统计：真实的 **Network**（它只根据单条消息确认更新）和 **Encode**（每帧从
  抓屏到编码完成的耗时）
- 应用层控制消息与视频消息格式
- Wayland 下通过 `xdg-desktop-portal` 的 ScreenCast portal + PipeWire 抓屏，x264 编码 H.264，
  30 fps
- **按原生分辨率编码，不拉伸画面。** 桌面按它自己的尺寸编码，只有超过 1920×1080 时才等比
  缩小（Parsec 官方被控端就是这么做的），并向下取偶以保证 x264 能启动。真实尺寸写在每一帧的
  帧头里。
- 任意桌面分辨率，包括推流过程中改变分辨率：编码尺寸在抓屏启动时固定，所以改变窗口大小不会
  重建编码器，也不会断开连接
- **鼠标和键盘输入**，通过 `uinput` 创建一个绝对坐标指针设备和一个键盘设备来注入

## 尚未实现

- **滚轮和手柄**：消息能解析，但字段布局是从 SDK 的枚举推算出来的，没有在实际流量里观察到。
  `parsec4linux/input.py` 会标记哪些消息是已确认的，被控端遇到推测布局时会打日志，所以猜错
  会暴露出来，而不是悄悄注入错误的输入。
- **客户端请求分辨率。** 客户端可以要求被控端改变屏幕分辨率（配置消息里的 `resolutionX` /
  `resolutionY`），我们忽略了它。因此连接过程中改变桌面分辨率不会重新选择编码尺寸，要重启
  被控端才会生效。
- **检测客户端已断开。** 被控端会一直推流到运行时间结束；Parsec 官方被控端在 60 秒收不到
  任何数据包后就会放弃。
- 音频 —— 通道 2，消息类型 `0x01`
- 鼠标指针形状（客户端始终显示普通箭头）、剪贴板、多客户端

## 文件结构

| 路径 | 作用 |
|---|---|
| `parsec4linux/bud.py` | BUD 记录层加解密与封装 |
| `parsec4linux/reliable.py` | 可靠通道：分片与重组 |
| `parsec4linux/feedback.py` | 83 字节的确认包：`0x08`（累积）和 `0x02`（单条消息） |
| `parsec4linux/app.py` | 13 字节控制消息头 |
| `parsec4linux/video.py` | 10 字节视频帧头、关键帧判定、编码尺寸选择 |
| `parsec4linux/input.py` | 客户端到被控端的输入消息、Parsec 到 Linux 的键码映射 |
| `tools/kessel_probe.py` | 被控端主程序：信令、ICE、BUD、发送视频 |
| `tools/capture_h264.py` | 抓屏 + 编码（PipeWire portal 或测试图案） |
| `tools/inject_input.py` | 通过 `/dev/uinput` 把输入注入桌面 |
| `tools/parsec_client.py` | 一个客户端，连到真实被控端并解密它的流量 |
| `tools/validate_capture.py` | 把抓包重放过一遍封装逻辑做校验 |
| `tools/retransmit_stats.py` | 从抓包统计重传情况 |
| `re/NOTES.md` | 协议笔记：线上格式、实测常量、以及哪些还没验证 |

`parsec4linux/` 下每个模块都有自测：`python -m parsec4linux.<模块名>`。

`tools/parsec_client.py` 值得单独说一下。视频帧头里有几个字段（`kind`、`flags`、`+0`）是编码
后端在**运行时**生成的，根本无法从二进制里静态读出来。靠猜是不行的。这个工具会连上一台真实
的被控端——对方会在 `answer` 里把 BUD 会话密钥交出来——然后把解密后的流量导出来，真实取值就
可以直接从线上读到。**实测胜过反汇编**，后来输入消息的格式也是用同样的思路、从被控端自己的
日志里定下来的。

## 运行方法

**Linux 这边不需要安装 Parsec。** 这个被控端是纯 Python 实现，不会加载任何 Parsec 的代码，它
只是在网络上说同样的协议。你真正需要的是：

- 一个 **Parsec 账号**，被控端要登录 Parsec 自己的服务器才能被列出来
- 你**连出去**的那台机器上装有普通的 **Parsec 客户端**
- Python 3.12+、`websockets`、`cryptography`
- `gstreamer1.0-plugins-{good,bad,ugly}`，提供 `x264enc` / `h264parse`
- 输入功能需要 `/dev/uinput` 的写权限：
  ```sh
  sudo setfacl -m u:$USER:rw /dev/uinput          # 重启前有效
  # 永久生效：
  echo 'KERNEL=="uinput", MODE="0660", GROUP="input", OPTIONS+="static_node=uinput"' \
    | sudo tee /etc/udev/rules.d/99-parsec4linux-uinput.rules
  sudo usermod -aG input $USER                     # 然后重新登录
  ```

```sh
# 凭据文件：~/.config/parsec4linux/creds.json  {"email": "...", "password": "..."}
python tools/kessel_probe.py auth

# 开始共享桌面（Wayland 下第一次需要手动同意“共享屏幕”弹窗）
python tools/kessel_probe.py ws --answer --port 8000 --fps 30 \
    --name my-linux-host \
    --inject "python3 tools/inject_input.py --desktop 2554x1367" \
    --capture "python3 tools/capture_h264.py --source pipewire \
               --fps 30 --keyint 30 --bitrate 3000"
```

然后用任意 Parsec 客户端连接 `my-linux-host`。

关于命令行的几点说明：

- 编码尺寸是**自动探测**的，不需要指定。`--max-w` / `--max-h`（默认 1920×1080）是上限；
  `--native-off` 可以退回到以前那种固定 `--width`×`--height` 的行为。
- `--desktop WxH` 要填你真实的桌面分辨率。它把绝对坐标轴的范围声明成屏幕尺寸，让合成器
  1:1 映射，这样注入的指针才能和客户端自己画的指针对齐。
- 不想接受输入，就去掉 `--inject`。
- 抓屏必须用系统的 `python3`，因为它需要 `gi`（PyGObject），虚拟环境里一般没有；被控端本身
  可以跑在 venv 里。
- `python3 tools/inject_input.py --selftest` 可以在不连客户端的情况下单独测试输入注入——它会
  让鼠标走一个正方形。
- `--source videotestsrc` 改为推送测试图案，不需要屏幕共享授权，是把协议问题和抓屏问题分开
  排查的正确做法。
- `--cursor hidden` 让画面里不含真实鼠标指针（Parsec 就是这么做的），这样你只会看到客户端
  自己画的那一个。`embedded` 会同时显示两个，正好用来检查它们是否对齐。

## 项目定位

这是一个个人自用的互操作性项目：在厂商不支持的平台上跑被控端，和厂商自己的客户端通信，用的是
作者自己的账号。本项目与 Parsec/Unity 无关，也未获得其认可。使用前请自行确认 Parsec 的服务
条款，不要用它去连接不属于你的账号或机器。
