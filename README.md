# MARC 查看器（本地桌面程序）

该工具用于加载中国图书馆机读目录（MARC）文件，逐条浏览记录，并支持前后翻动与跳转。

## 功能
- 选择 `.marc`/`.mrc`/`.iso`/`.cnmarc` 文件
- 加载记录并显示要点字段（题名、责任者、作者、出版、ISBN、索书号等）
- 显示完整字段明细
- 支持上一条 / 下一条 和输入序号跳转；方向键 ←/→ 也可切换

## 依赖安装
建议使用 Python 3.10+。

```bash
cd /Users/chun/AILibrary/marc
python3 -m pip install -r requirements.txt
```

## 运行
```bash
cd /Users/chun/AILibrary/marc
python3 marc_viewer.py
```

## 使用说明
1. 点击「打开文件」，选择需要查看的 MARC 文件（例如 `outmarc20250703105329.marc`）。
2. 程序会解析并加载所有记录：
   - 顶部显示当前记录位置，例如 `记录 1/120`
   - 文本区域会显示当前记录的核心字段与全部字段
3. 使用「上一条」「下一条」或键盘方向键进行前后翻动；也可在跳转框输入目标序号并回车跳转。

## 编码与兼容
- 程序使用 `pymarc.MARCReader`，启用了 `to_unicode=True, force_utf8=True, utf8_handling="replace", permissive=True`，可兼容常见 UTF-8 / MARC-8 情况。
- 如遇到文件编码或格式特殊导致的解析失败，请提供样例文件或格式说明以便进一步完善解析策略（例如特定 CNMARC 变体）。
