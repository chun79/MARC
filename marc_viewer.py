#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText

try:
	from pymarc import MARCReader
except Exception as import_error:
	MARCReader = None
	_import_error = import_error
else:
	_import_error = None


class MarcViewerApp:
	def __init__(self, root: tk.Tk, initial_dir: str | None = None) -> None:
		self.root = root
		self.root.title("MARC 查看器")
		self.root.minsize(1200, 800)
		# 默认更大的窗口尺寸，尽可能完整显示一条记录
		try:
			self.root.geometry("1400x900")
		except Exception:
			pass

		self.initial_dir = initial_dir or os.getcwd()
		self.current_index: int = -1
		self.file_path: str | None = None
		self._fh = None  # 持久文件句柄
		self._spans: list[tuple[int, int]] = []  # 每条记录的 (start, end) 字节区间，end 为终止符后一位

		self._build_ui()
		self._bind_shortcuts()
		self.root.protocol("WM_DELETE_WINDOW", self._on_close)

	def _build_ui(self) -> None:
		top_bar = ttk.Frame(self.root)
		top_bar.pack(side=tk.TOP, fill=tk.X, padx=8, pady=6)

		self.open_btn = ttk.Button(top_bar, text="打开文件", command=self.open_file)
		self.open_btn.pack(side=tk.LEFT)

		self.filename_label_var = tk.StringVar(value="未打开文件")
		self.filename_label = ttk.Label(top_bar, textvariable=self.filename_label_var)
		self.filename_label.pack(side=tk.LEFT, padx=10)

		# Navigation controls
		nav_bar = ttk.Frame(self.root)
		nav_bar.pack(side=tk.TOP, fill=tk.X, padx=8, pady=0)

		self.prev_btn = ttk.Button(nav_bar, text="上一条 ←", command=self.prev_record, state=tk.DISABLED)
		self.prev_btn.pack(side=tk.LEFT)

		self.next_btn = ttk.Button(nav_bar, text="下一条 →", command=self.next_record, state=tk.DISABLED)
		self.next_btn.pack(side=tk.LEFT, padx=(6, 0))

		self.position_var = tk.StringVar(value="记录 0/0")
		self.position_label = ttk.Label(nav_bar, textvariable=self.position_var)
		self.position_label.pack(side=tk.LEFT, padx=10)

		# Encoding selector
		self.encoding_var = tk.StringVar(value="自动")
		self.encoding_combo = ttk.Combobox(
			nav_bar,
			textvariable=self.encoding_var,
			values=["自动", "UTF-8", "GB18030", "GBK", "GB2312", "MARC-8"],
			width=10,
			state="readonly",
		)
		self.encoding_combo.pack(side=tk.LEFT, padx=(12, 0))
		self.encoding_combo.bind("<<ComboboxSelected>>", lambda _e: self._render_current())

		# Format selector
		self.format_var = tk.StringVar(value="自动")
		self.format_combo = ttk.Combobox(
			nav_bar,
			textvariable=self.format_var,
			values=["自动", "CNMARC/UNIMARC", "MARC21"],
			width=14,
			state="readonly",
		)
		self.format_combo.pack(side=tk.LEFT, padx=(8, 0))
		self.format_combo.bind("<<ComboboxSelected>>", lambda _e: self._render_current())

		# Jump to index
		self.jump_var = tk.StringVar()
		self.jump_entry = ttk.Entry(nav_bar, textvariable=self.jump_var, width=8)
		self.jump_entry.pack(side=tk.LEFT, padx=(12, 0))
		self.jump_entry.insert(0, "1")
		self.jump_btn = ttk.Button(nav_bar, text="跳转", command=self.jump_to)
		self.jump_btn.pack(side=tk.LEFT, padx=(6, 0))

		self.text = ScrolledText(self.root, wrap=tk.WORD, font=("Menlo", 12))
		self.text.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=8, pady=8)
		# Prefer a CJK-capable font on macOS to avoid missing glyphs
		try:
			self.text.configure(font=("PingFang SC", 12))
		except Exception:
			pass
		self._set_text_readonly(True)

	def _bind_shortcuts(self) -> None:
		self.root.bind("<Left>", lambda _e: self.prev_record())
		self.root.bind("<Right>", lambda _e: self.next_record())
		self.root.bind("<Return>", lambda _e: self.jump_to())

	def _set_text_readonly(self, readonly: bool) -> None:
		if readonly:
			self.text.config(state=tk.DISABLED)
		else:
			self.text.config(state=tk.NORMAL)

	def open_file(self) -> None:
		if MARCReader is None:
			messagebox.showerror("缺少依赖", f"未能导入 pymarc: {_import_error}\n请先安装依赖: pip install -r requirements.txt")
			return

		file_path = filedialog.askopenfilename(
			title="选择 MARC 文件",
			initialdir=self.initial_dir,
			filetypes=[
				("MARC 文件", "*.marc *.mrc *.iso *.cnmarc"),
				("所有文件", "*.*"),
			],
		)
		if not file_path:
			return

		self.load_records(file_path)

	def load_records(self, file_path: str) -> None:
		# 关闭旧文件
		if self._fh is not None:
			try:
				self._fh.close()
			except Exception:
				pass
			self._fh = None

		# 打开新文件并构建记录索引（基于 0x1D 记录终止符）
		try:
			self._fh = open(file_path, "rb")
		except Exception as e:
			messagebox.showerror("读取失败", f"无法打开文件:\n{e}")
			return

		try:
			self._spans = self._build_spans(self._fh)
		except Exception as e:
			messagebox.showerror("读取失败", f"构建索引失败:\n{e}")
			self._spans = []

		if not self._spans:
			messagebox.showwarning("无记录", "未找到任何记录终止符 (0x1D)，或文件不符合预期格式。")
			return

		self.current_index = 0
		self.file_path = file_path
		self.filename_label_var.set(os.path.basename(file_path))
		self._update_nav_state()
		self._render_current()

	def _update_nav_state(self) -> None:
		length = len(self._spans)
		pos = (self.current_index + 1) if length else 0
		self.position_var.set(f"记录 {pos}/{length}")

		self.prev_btn.config(state=(tk.NORMAL if self.current_index > 0 else tk.DISABLED))
		self.next_btn.config(state=(tk.NORMAL if self.current_index < length - 1 else tk.DISABLED))

	def _render_current(self) -> None:
		self._set_text_readonly(False)
		self.text.delete("1.0", tk.END)
		if 0 <= self.current_index < len(self._spans):
			record, parse_mode = self._read_and_parse(self.current_index)
			if record is not None:
				fmt_mode = self._decide_format(record)
				self.text.insert(tk.END, self._format_record(record, parse_mode, fmt_mode))
			else:
				self.text.insert(tk.END, "当前记录解析失败（展示原始十六进制预览）\n\n" + self._hex_preview(self.current_index))
		else:
			self.text.insert(tk.END, "未选中记录")
		self._set_text_readonly(True)
		self._update_nav_state()

	def prev_record(self) -> None:
		if self.current_index > 0:
			self.current_index -= 1
			self._render_current()

	def next_record(self) -> None:
		if self.current_index < len(self._spans) - 1:
			self.current_index += 1
			self._render_current()

	def jump_to(self) -> None:
		text = self.jump_var.get().strip()
		if not text.isdigit():
			messagebox.showinfo("提示", "请输入有效的序号（正整数）。")
			return
		idx = int(text) - 1
		if not (0 <= idx < len(self._spans)):
			messagebox.showinfo("提示", f"请输入 1 到 {len(self._spans)} 之间的序号。")
			return
		self.current_index = idx
		self._render_current()

	def _on_close(self) -> None:
		try:
			if self._fh is not None:
				self._fh.close()
		except Exception:
			pass
		self.root.destroy()

	def _build_spans(self, fh) -> list[tuple[int, int]]:
		# 基于 0x1D 扫描，得到每条记录的字节区间 (start, end)
		spans: list[tuple[int, int]] = []
		fh.seek(0, os.SEEK_END)
		total = fh.tell()
		fh.seek(0)
		block_size = 4 * 1024 * 1024
		start = 0
		position = 0
		while True:
			chunk = fh.read(block_size)
			if not chunk:
				break
			offset = 0
			while True:
				idx = chunk.find(b"\x1d", offset)
				if idx == -1:
					break
				end_abs = position + idx + 1  # 包含终止符后一位
				spans.append((start, end_abs))
				start = end_abs
				offset = idx + 1
			position += len(chunk)
		# 忽略末尾未以 0x1D 结束的残余
		return spans

	def _read_span(self, index: int) -> bytes:
		start, end = self._spans[index]
		self._fh.seek(start)
		return self._fh.read(end - start)

	def _read_and_parse(self, index: int):
		data = self._read_span(index)
		data = self._trim_leading(data)
		mode = self.encoding_var.get() if hasattr(self, 'encoding_var') else '自动'
		try:
			if mode == 'UTF-8':
				reader = MARCReader(data, to_unicode=True, force_utf8=True, utf8_handling="replace", permissive=True)
				rec = next(reader, None)
				return rec, 'UTF-8'
			elif mode == 'MARC-8':
				reader = MARCReader(data, to_unicode=True, force_utf8=False, utf8_handling="replace", permissive=True)
				rec = next(reader, None)
				return rec, 'MARC-8'
			elif mode in ('GB18030', 'GBK', 'GB2312'):
				# 先按原始字节解析，再按所选国标编码逐字段解码
				reader = MARCReader(data, to_unicode=False, force_utf8=False, permissive=True)
				rec = next(reader, None)
				if rec is not None:
					enc_map = {
						'GB18030': 'gb18030',
						'GBK': 'gbk',
						'GB2312': 'gb2312',
					}
					self._convert_record_to_encoding(rec, enc_map[mode])
				return rec, mode
			else:  # 自动
				# 优先 GB18030（CNMARC 常见），再 UTF-8，最后 MARC-8
				reader = MARCReader(data, to_unicode=False, force_utf8=False, permissive=True)
				rec = next(reader, None)
				if rec is not None:
					self._convert_record_to_encoding(rec, 'gb18030')
					return rec, 'GB18030'
				# 再尝试 UTF-8
				reader = MARCReader(data, to_unicode=True, force_utf8=True, utf8_handling="replace", permissive=True)
				rec = next(reader, None)
				if rec is not None:
					return rec, 'UTF-8'
				# 最后尝试 MARC-8
				reader = MARCReader(data, to_unicode=True, force_utf8=False, utf8_handling="replace", permissive=True)
				rec = next(reader, None)
				if rec is not None:
					return rec, 'MARC-8'
				return None, 'AUTO_FAIL'
		except Exception:
			return None, 'ERROR'

	def _hex_preview(self, index: int, max_len: int = 1024) -> str:
		data = self._read_span(index)[:max_len]
		return data.hex(" ")

	def _trim_leading(self, data: bytes) -> bytes:
		# 去除记录前的换行、空格、NUL 等填充
		if not data:
			return data
		pad = {0x00, 0x0d, 0x0a, 0x20}
		i = 0
		ln = len(data)
		while i < ln and data[i] in pad:
			i += 1
		data = data[i:]
		# 若前 5 字节不是数字，尝试在前 256 字节内寻找第一个 5 连续数字作为 leader 起点
		if len(data) >= 5 and not all(48 <= c <= 57 for c in data[:5]):
			limit = min(256, len(data) - 5)
			found = -1
			for j in range(0, limit):
				seg = data[j:j+5]
				if all(48 <= c <= 57 for c in seg):
					found = j
					break
			if found > 0:
				data = data[found:]
		return data

	@staticmethod
	def _sf_decode(val, preferred_encoding: str | None) -> str:
		try:
			if isinstance(val, (bytes, bytearray)):
				b = bytes(val)
				if preferred_encoding:
					return b.decode(preferred_encoding, errors='replace')
				# fallback: try utf-8 then gb18030
				try:
					return b.decode('utf-8')
				except Exception:
					return b.decode('gb18030', errors='replace')
			return str(val)
		except Exception:
			return ''

	def _sf(self, field, code: str) -> str:
		try:
			vals = field.get_subfields(code)
			enc_choice = self.encoding_var.get() if hasattr(self, 'encoding_var') else '自动'
			enc_map = {
				'UTF-8': 'utf-8',
				'GB18030': 'gb18030',
				'GBK': 'gbk',
				'GB2312': 'gb2312',
				'MARC-8': None,
				'自动': None,
			}
			preferred = enc_map.get(enc_choice, None)
			return " ".join(self._sf_decode(v, preferred) for v in vals if v)
		except Exception:
			return ""

	def _format_record(self, record, parse_mode: str = '', format_mode: str = '') -> str:
		lines: list[str] = []
		try:
			leader = getattr(record, "leader", "") or ""
			lines.append(f"LEADER: {leader}")
		except Exception:
			pass

		# Prefer mapping based on selected/detected format
		is_unimarc = (format_mode == 'CNMARC')

		title = responsibility = ""
		author = ""
		publisher = year = ""
		isbn = ""
		callno = ""

		if is_unimarc:
			# 200: 题名与责任者
			fs_200 = record.get_fields("200")
			if fs_200:
				f = fs_200[0]
				# 题名：a 正题名，e 其他题名信息，d 并列正题名
				title = "".join([self._sf(f, "a"), self._sf(f, "e"), self._sf(f, "d")]).strip()
				# 责任者：f 第一责任者，g 其他责任说明
				responsibility = " ".join([self._sf(f, "f"), self._sf(f, "g")]).strip()

			# 责任者字段：700/701/702（个人），710/711（团体/会议）
			for tag in ("700", "701", "702", "710", "711"):
				fs = record.get_fields(tag)
				if fs:
					f = fs[0]
					author = self._sf(f, "a")
					if not author:
						author = self._sf(f, "b")
					break

			# 出版项：210 a 出版地，c 出版者，d 出版年
			fs_210 = record.get_fields("210")
			if fs_210:
				f = fs_210[0]
				place = self._sf(f, "a")
				publisher = self._sf(f, "c")
				year = self._sf(f, "d")
				# 若有出版地则合并显示
				if place and publisher:
					publisher = f"{place}: {publisher}"

			# ISBN：010 a
			fs_010 = record.get_fields("010")
			if fs_010:
				isbn = self._sf(fs_010[0], "a")

			# 索书号/分类：686/690 a
			for tag in ("686", "690"):
				fs = record.get_fields(tag)
				if fs:
					callno = self._sf(fs[0], "a")
					break
		else:
			# MARC21 兼容路径
			field_245 = record.get_fields("245")
			if field_245:
				f = field_245[0]
				title = "".join([self._sf(f, "a"), self._sf(f, "b"), self._sf(f, "n"), self._sf(f, "p")]).strip()
				responsibility = self._sf(f, "c")

			for tag in ("100", "110", "111"):
				fs = record.get_fields(tag)
				if fs:
					f = fs[0]
					author = self._sf(f, "a")
					break

			for tag in ("264", "260"):
				fs = record.get_fields(tag)
				if fs:
					f = fs[0]
					publisher = self._sf(f, "b")
					year = self._sf(f, "c")
					break

			fs_020 = record.get_fields("020")
			if fs_020:
				isbn = self._sf(fs_020[0], "a")

			for tag in ("090", "082", "084"):
				fs = record.get_fields(tag)
				if fs:
					callno = self._sf(fs[0], "a")
					break

		if title:
			lines.append(f"标题: {title}")
		if responsibility:
			lines.append(f"题名责任者: {responsibility}")
		if author:
			lines.append(f"作者/团体: {author}")
		if publisher:
			lines.append(f"出版者: {publisher}")
		if year:
			lines.append(f"出版年: {year}")
		if isbn:
			lines.append(f"ISBN: {isbn}")
		if callno:
			lines.append(f"索书号: {callno}")

		lines.append("")
		mode_note = f"（{parse_mode}）" if parse_mode else ""
		fmt_note = f"[{format_mode}]" if format_mode else ""
		lines.append(f"— 全部字段 — {mode_note} {fmt_note}")
		try:
			for f in record.get_fields():
				if f.is_control_field():
					data_val = getattr(f, 'data', '')
					enc_choice = self.encoding_var.get() if hasattr(self, 'encoding_var') else '自动'
					enc_map = {
						'UTF-8': 'utf-8',
						'GB18030': 'gb18030',
						'GBK': 'gbk',
						'GB2312': 'gb2312',
						'MARC-8': None,
						'自动': None,
					}
					preferred = enc_map.get(enc_choice, None)
					if isinstance(data_val, (bytes, bytearray)):
						data_str = self._sf_decode(data_val, preferred)
					else:
						data_str = str(data_val)
					lines.append(f"{f.tag} {data_str}")
					continue
				# variable fields: handle pymarc 5 Subfield objects
				subs = []
				if hasattr(f, 'subfields'):
					# pymarc 5: list[Subfield]
					for sf in f.subfields:
						code = getattr(sf, 'code', None)
						val = getattr(sf, 'value', None)
						enc_choice = self.encoding_var.get() if hasattr(self, 'encoding_var') else '自动'
						enc_map = {
							'UTF-8': 'utf-8',
							'GB18030': 'gb18030',
							'GBK': 'gbk',
							'GB2312': 'gb2312',
							'MARC-8': None,
							'自动': None,
						}
						preferred = enc_map.get(enc_choice, None)
						val_str = self._sf_decode(val, preferred)
						subs.append(f"${code} {val_str}")
				else:
					# fallback old style
					for i in range(0, len(f.subfields), 2):
						code = f.subfields[i]
						val = f.subfields[i + 1] if i + 1 < len(f.subfields) else ""
						enc_choice = self.encoding_var.get() if hasattr(self, 'encoding_var') else '自动'
						enc_map = {
							'UTF-8': 'utf-8',
							'GB18030': 'gb18030',
							'GBK': 'gbk',
							'GB2312': 'gb2312',
							'MARC-8': None,
							'自动': None,
						}
						preferred = enc_map.get(enc_choice, None)
						val_str = self._sf_decode(val, preferred)
						subs.append(f"${code} {val_str}")
				ind1 = getattr(f, 'indicator1', ' ')
				ind2 = getattr(f, 'indicator2', ' ')
				lines.append(f"{f.tag} {ind1}{ind2} " + " ".join(subs))
		except Exception:
			pass

		return "\n".join(lines) + "\n"

	def _decide_format(self, rec) -> str:
		# 用户手动选择优先；自动时依据字段判断
		try:
			choice = self.format_var.get()
		except Exception:
			choice = '自动'
		if choice == 'MARC21':
			return 'MARC21'
		if choice == 'CNMARC/UNIMARC':
			return 'CNMARC'
		# 自动：依据是否存在 200/210/010 判定 CNMARC，否则如果存在 245/260/264/020 则判定 MARC21
		try:
			if rec is not None:
				if rec.get_fields('200') or rec.get_fields('210') or rec.get_fields('010'):
					return 'CNMARC'
				if rec.get_fields('245') or rec.get_fields('260') or rec.get_fields('264') or rec.get_fields('020'):
					return 'MARC21'
		except Exception:
			pass
		# 默认按 CNMARC 处理（你的文件是确定的 CNMARC）
		return 'CNMARC'

	def _convert_record_to_encoding(self, record, encoding: str) -> None:
		# 将 to_unicode=False 获得的原始字节逐字段转换为目标编码字符串
		try:
			for f in record.get_fields():
				if f.is_control_field():
					if isinstance(getattr(f, 'data', None), (bytes, bytearray)):
						try:
							f.data = bytes(f.data).decode(encoding, errors='replace')
						except Exception:
							pass
					continue
				if hasattr(f, 'subfields') and isinstance(f.subfields, list):
					for i in range(1, len(f.subfields), 2):
						val = f.subfields[i]
						if isinstance(val, (bytes, bytearray)):
							try:
								f.subfields[i] = bytes(val).decode(encoding, errors='replace')
							except Exception:
								pass
		except Exception:
			pass


def main() -> int:
	if MARCReader is None:
		print(f"未能导入 pymarc: {_import_error}")
		print("请先运行: pip install -r requirements.txt")
		return 1

	root = tk.Tk()
	app = MarcViewerApp(root, initial_dir=os.getcwd())

	# 如果当前目录存在常见文件名，友好提示加载
	common_candidates = [
		"outmarc20250703105329.marc",
	]
	for name in common_candidates:
		path = os.path.join(os.getcwd(), name)
		if os.path.exists(path) and os.path.isfile(path):
			app.filename_label_var.set(f"可打开: {name}")
			break

	root.mainloop()
	return 0


if __name__ == "__main__":
	sys.exit(main())
