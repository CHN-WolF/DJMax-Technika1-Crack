# DJMax Technika 1 中国版 client.exe 破甲工作档案

> **本仓库只含源代码与文档**,便于复现。游戏本体/资源、构建产物(*.exe/*.dll)、
> 内存快照(`analysis/`、`oepdump_out/`)、工具链(`tools/toolchain/`)、
> 第三方环境(`olly110/`)均不上传——请用你自己的游戏安装并按文档重新生成。
> 编译用 [w64devkit](https://github.com/skeeto/w64devkit)(解压到 `tools/toolchain/w64devkit_x/`,gcc -m32)。

**权威文档:[总结_免狗与脱壳.md](总结_免狗与脱壳.md)** —— 免狗与脱壳的原理、复现步骤、
修复史与完整文件清单全部在其中,照做可复现。

快速入口:

- 玩游戏(免狗):游戏根目录 `Client_Online.bat`
- 玩脱壳版:游戏根目录 `run_unpacked.bat`
- 分发包:游戏根目录 `DJMax Technika 1 China Version.zip`
- 免狗组件源码:`tools/rcreplay.c`、`tools/rclocal_diag.c`
- 脱壳组件源码:`tools/oepdump.c`、`tools/build_unp.c`、`tools/selfredir.c`、`tools/run_unpacked.c`
- 真狗交互记录(回放数据来源):`analysis/rclog_realdog_full.txt`
- 资源提取(离线、全量、带原始文件名):`tools/tpkx.exe <file.tpk> <outdir>`,产物在根目录 `extracted/`(见总结 2.7 节)
- 谱面解密(离线):`tools/ptffx.exe <p02文件> <out.pt>`,产物在 `extracted_pt/`(262 个 .pt,带 PTFF 头,编辑器可直接读;算法与 DMTQ-Tools/pt_to_text 的 PtCipher 一致)
- 构建工具链:`tools/toolchain/w64devkit_x/`(gcc -m32)
