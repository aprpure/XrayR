
# XrayR
[![](https://img.shields.io/badge/TgChat-@UnOfficialV2board讨论-blue.svg)](https://t.me/unofficialV2board)
[![](https://img.shields.io/badge/TgChat-@XrayR讨论-blue.svg)](https://t.me/XrayR_project)
[![](https://img.shields.io/badge/Channel-@XrayR通知-blue.svg)](https://t.me/XrayR_channel)
![](https://img.shields.io/github/stars/aprpure/XrayR)
![](https://img.shields.io/github/forks/aprpure/XrayR)
![](https://github.com/aprpure/XrayR/actions/workflows/release.yml/badge.svg)
[![Github All Releases](https://img.shields.io/github/downloads/aprpure/XrayR/total.svg)]()


A Xray backend framework that can easily support many panels. **This branch is designed for the [Xboard](https://github.com/cedar2025/Xboard) panel.**

一个基于Xray的后端框架，**本分支适用于 [Xboard](https://github.com/cedar2025/Xboard) 面板**，支持 V2ray(Vmess/Vless)、Trojan、Shadowsocks、Hysteria2 协议，极易扩展，支持多面板对接。

如果您喜欢本项目，可以右上角点个star+watch，持续关注本项目的进展。

使用教程：[详细使用教程](https://xrayr-project.github.io/XrayR-doc/)


## 免责声明

本项目只是本人个人学习开发并维护，本人不保证任何可用性，也不对使用本软件造成的任何后果负责。

## 特点

* 永久开源且免费。
* 支持V2ray，Trojan， Shadowsocks，Hysteria2 多种协议。
* 支持Vless和XTLS、REALITY等新特性。
* 适配Xboard面板V2节点API，旧版面板自动回退V1接口。
* 支持单实例对接多面板、多节点，无需重复启动。
* 支持限制在线IP
* 支持节点端口级别、用户级别限速。
* 配置简单明了。
* 修改配置自动重启实例。
* 方便编译和升级，可以快速更新核心版本， 支持Xray-core新特性。

## 功能介绍

| 功能        | vmess | vless | trojan | shadowsocks | hysteria2 |
|-----------|-------|-------|--------|-------------|-----------|
| 获取节点信息| √ | √ | √ |√ | √ |
| 获取用户信息| √ | √ | √ |√ | √ |
| 用户流量统计| √ | √ | √ |√ | √ |
| 服务器信息上报| √ | √ | √ |√ | √ |
| 自动申请tls证书| √ | √ | √ |√ | √ |
| 自动续签tls证书| √ | √ | √ |√ | √ |
| 在线人数统计| √ | √ | √ |√ | √ |
| 在线用户限制| √ | √ | √ |√ | - |
| 审计规则| √ | √ | √ |√ | √ |
| 节点端口限速| √ | √ | √ |√ | √ (brutal) |
| 按照用户限速| √ | √ | √ |√ | - |
| 自定义DNS| √ | √ | √ |√ | √ |

## 支持前端


| 前端                                                     | vmess | vless | trojan | shadowsocks | hysteria2 |
|--------------------------------------------------------|-------|-------|--------|-------------------------|-----------|
| **[Xboard](https://github.com/cedar2025/Xboard)**（本分支主要适配）    | √     | √     | √      | √            | √         |
| sspanel-uim                                            | √     | √     | √      | √ (单端口多用户和V2ray-Plugin) | - |
| v2board                                                | √     | √     | √      | √                       | - |
| [PMPanel](https://github.com/ByteInternetHK/PMPanel)   | √     | √     | √      | √                       |
| [ProxyPanel](https://github.com/ProxyPanel/ProxyPanel) | √     | √     | √      | √                       |
| [WHMCS (V2RaySocks)](https://v2raysocks.doxtex.com/)   | √     | √     | √      | √                       |
| [GoV2Panel](https://github.com/pingProMax/gov2panel)   | √     | √     | √      | √                       |
| [BunPanel](https://github.com/pennyMorant/bunpanel-release)   | √     | √     | √      | √                       |

## 软件安装

### 一键安装

```
wget -N https://raw.githubusercontent.com/aprpure/XrayR-release/master/install.sh && bash install.sh
```

### 手动安装

[手动安装教程](https://xrayr-project.github.io/XrayR-doc/xrayr-xia-zai-he-an-zhuang/install/manual)

## 配置文件及详细使用教程

[详细使用教程](https://xrayr-project.github.io/XrayR-doc/)

## Thanks

* [Project X](https://github.com/XTLS/)
* [V2Fly](https://github.com/v2fly)
* [VNet-V2ray](https://github.com/ProxyPanel/VNet-V2ray)
* [Air-Universe](https://github.com/crossfw/Air-Universe)

## Licence

[Mozilla Public License Version 2.0](https://github.com/aprpure/XrayR/blob/master/LICENSE)

## Telgram

[XrayR后端讨论](https://t.me/XrayR_project)

[XrayR通知](https://t.me/XrayR_channel)

## Stargazers over time

[![Stargazers over time](https://starchart.cc/aprpure/XrayR.svg)](https://starchart.cc/aprpure/XrayR)


