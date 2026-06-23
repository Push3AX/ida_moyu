"""
ida_moyu

Install:
  Copy this file into IDA's plugins directory, then restart IDA.

Usage:
  Edit -> Plugins -> ida_moyu, or Ctrl+Alt+M.
  Enter an http(s) URL, a local text/html file path, or paste text.

The plugin creates an IDA dockable tab with a pseudocode-like reader. URL
sources are masked in the input bar and rendered source text after loading.
"""

import datetime
import html
import os
import re
import traceback
from html.parser import HTMLParser
from urllib.error import URLError
from urllib.parse import quote, unquote, urljoin, urlparse
from urllib.request import Request, pathname2url, url2pathname, urlopen

import idaapi
import ida_funcs
import ida_kernwin
import idc


PLUGIN_NAME = "ida_moyu"
ACTION_OPEN = "ida_moyu:open"
MAX_FETCH_BYTES = 2 * 1024 * 1024
MAX_RENDERED_LINES = 4000

_FORM = None
_QT = None


def _qt():
    global _QT
    if _QT is not None:
        return _QT

    last_error = None
    for binding in ("PyQt5", "PySide6", "PySide2"):
        try:
            if binding == "PyQt5":
                from PyQt5 import QtCore, QtGui, QtWidgets
            elif binding == "PySide6":
                from PySide6 import QtCore, QtGui, QtWidgets
            else:
                from PySide2 import QtCore, QtGui, QtWidgets
            _QT = (QtCore, QtGui, QtWidgets)
            return _QT
        except Exception as exc:
            last_error = exc

    raise RuntimeError("No supported Qt binding found in IDA Python: %r" % last_error)


def _current_ea():
    try:
        ea = ida_kernwin.get_screen_ea()
        if ea != idc.BADADDR:
            return ea
    except Exception:
        pass
    return 0x401000


def _current_func_label():
    try:
        ea = _current_ea()
        func = ida_funcs.get_func(ea)
        if func:
            name = getattr(ida_funcs, "get_func_name", idc.get_func_name)(func.start_ea)
            if name:
                return name
        name = idc.get_func_name(ea)
        if name:
            return name
    except Exception:
        pass
    return "sub_401000"


def _fake_source_label():
    ea = _current_ea()
    func = _current_func_label()
    return "%s+0x%X" % (func, ea & 0xFFF)


def _plugin_title():
    return "Pseudocode-%s" % _current_func_label()


def _text_cursor_start():
    QtCore, QtGui, QtWidgets = _qt()
    start = getattr(QtGui.QTextCursor, "Start", None)
    if start is None:
        start = QtGui.QTextCursor.MoveOperation.Start
    return start


def _decode_bytes(data, content_type=""):
    charset = None
    m = re.search(r"charset=([A-Za-z0-9._-]+)", content_type or "", re.I)
    if m:
        charset = m.group(1)

    candidates = []
    if charset:
        candidates.append(charset)
    candidates.extend(["utf-8", "gb18030", "big5", "latin-1"])

    for enc in candidates:
        try:
            return data.decode(enc)
        except Exception:
            continue
    return data.decode("utf-8", "replace")


def _looks_like_html(text, content_type=""):
    ctype = (content_type or "").lower()
    if "html" in ctype or "xml" in ctype:
        return True
    sample = text[:4096].lower()
    return "<html" in sample or "<!doctype html" in sample or "<body" in sample


def _is_url(value):
    return value.lower().startswith(("http://", "https://"))


def _is_file_url(value):
    return value.lower().startswith("file://")


def _file_url_to_path(value):
    parsed = urlparse(value)
    path = url2pathname(unquote(parsed.path))
    if parsed.netloc and parsed.netloc not in ("", "localhost"):
        path = "//%s%s" % (parsed.netloc, path)
    return path


def _path_to_file_url(path):
    return "file://%s" % pathname2url(os.path.abspath(path))


def _fetch_url(url):
    req = Request(
        url,
        headers={
            "User-Agent": (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/126.0.0.0 Safari/537.36"
            ),
            "Accept": "text/html,text/plain,application/xhtml+xml,*/*;q=0.7",
        },
    )
    with urlopen(req, timeout=12) as resp:
        data = resp.read(MAX_FETCH_BYTES + 1)
        truncated = len(data) > MAX_FETCH_BYTES
        if truncated:
            data = data[:MAX_FETCH_BYTES]
        content_type = resp.headers.get("content-type", "")
        final_url = resp.geturl()
    return data, content_type, final_url, truncated


def _read_local_file(path):
    with open(path, "rb") as f:
        data = f.read(MAX_FETCH_BYTES + 1)
    truncated = len(data) > MAX_FETCH_BYTES
    if truncated:
        data = data[:MAX_FETCH_BYTES]
    return data, "text/plain", os.path.abspath(path), truncated


def _sanitize_comment(text):
    return text.replace("*/", "* /")


def _sanitize_string(text):
    text = text.replace("\\", "\\\\").replace("\"", "\\\"")
    if len(text) > 90:
        text = text[:87] + "..."
    return text


def _escape_text(text):
    return html.escape(text, quote=False)


def _escape_attr(text):
    return html.escape(text, quote=True)


def _normalize_plain_text(text):
    text = html.unescape(text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"[ \t\f\v]+", " ", text)
    text = re.sub(r" *\n *", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    lines = [line.strip() for line in text.splitlines()]
    return "\n".join(line for line in lines if line)


class _HTMLFragmentExtractor(HTMLParser):
    BLOCK_TAGS = {
        "address", "article", "aside", "blockquote", "br", "dd", "div", "dl",
        "dt", "fieldset", "figcaption", "figure", "footer", "form", "h1", "h2",
        "h3", "h4", "h5", "h6", "header", "hr", "li", "main", "nav", "ol", "p",
        "pre", "section", "table", "tbody", "td", "tfoot", "th", "thead", "tr",
        "ul",
    }
    HEADING_TAGS = {"h1", "h2", "h3", "h4", "h5", "h6"}
    SKIP_TAGS = {"script", "style", "svg", "canvas", "noscript"}

    def __init__(self, base_url=""):
        HTMLParser.__init__(self, convert_charrefs=True)
        self.base_url = base_url
        self._html_parts = []
        self._plain_parts = []
        self._skip_depth = 0
        self._link_stack = []
        self._heading_depth = 0

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        attrs = dict(attrs)
        if tag in self.SKIP_TAGS:
            self._skip_depth += 1
            return
        if self._skip_depth:
            return

        if tag in self.BLOCK_TAGS:
            self._newline()
        if tag == "li":
            self._append_text("* ")
        if tag in self.HEADING_TAGS:
            self._heading_depth += 1
            self._html_parts.append('<span class="body-heading">')
        if tag == "a":
            href = (attrs.get("href") or "").strip()
            if href and not href.lower().startswith(("javascript:", "data:")):
                resolved = urljoin(self.base_url, href)
                self._html_parts.append('<a href="%s">' % _escape_attr(resolved))
                self._link_stack.append(True)
            else:
                self._link_stack.append(False)

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in self.SKIP_TAGS and self._skip_depth:
            self._skip_depth -= 1
            return
        if self._skip_depth:
            return

        if tag == "a" and self._link_stack:
            if self._link_stack.pop():
                self._html_parts.append("</a>")
        if tag in self.HEADING_TAGS and self._heading_depth:
            self._heading_depth -= 1
            self._html_parts.append("</span>")
        if tag in self.BLOCK_TAGS:
            self._newline()

    def handle_data(self, data):
        if self._skip_depth or not data:
            return
        self._append_text(data)

    def _append_text(self, data):
        data = re.sub(r"\s+", " ", data)
        self._html_parts.append(_escape_text(data))
        self._plain_parts.append(data)

    def _newline(self):
        if not self._html_parts or self._html_parts[-1] != "\n":
            self._html_parts.append("\n")
        if not self._plain_parts or self._plain_parts[-1] != "\n":
            self._plain_parts.append("\n")

    def fragment(self):
        for is_open in reversed(self._link_stack):
            if is_open:
                self._html_parts.append("</a>")
        if self._heading_depth:
            self._html_parts.extend(["</span>"] * self._heading_depth)
        text = "".join(self._html_parts)
        text = re.sub(r"[ \t]*\n[ \t]*", "\n", text)
        text = re.sub(r"\n{3,}", "\n\n", text)
        lines = [line.strip() for line in text.splitlines()]
        return "\n".join(line for line in lines if line)

    def plain_text(self):
        return _normalize_plain_text("".join(self._plain_parts))


def _html_to_fragment(text, base_url):
    parser = _HTMLFragmentExtractor(base_url)
    parser.feed(text)
    parser.close()
    fragment = parser.fragment()
    plain = parser.plain_text()
    if not fragment:
        plain = _normalize_plain_text(text)
        fragment = _text_to_fragment(plain)
    return fragment, plain


def _auto_link_escaped_line(line):
    pattern = re.compile(r"(?i)\b(?:https?://|file://)[^\s<>()\"']+")
    pos = 0
    parts = []
    for match in pattern.finditer(line):
        parts.append(_escape_text(line[pos:match.start()]))
        url = match.group(0).rstrip(".,;:]")
        suffix = match.group(0)[len(url):]
        parts.append('<a href="%s">%s</a>' % (_escape_attr(url), _escape_text(url)))
        parts.append(_escape_text(suffix))
        pos = match.end()
    parts.append(_escape_text(line[pos:]))
    return "".join(parts)


def _text_to_fragment(text):
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return "\n".join(_auto_link_escaped_line(line.rstrip()) for line in text.splitlines())


def _fragment_to_plain_text(fragment):
    text = re.sub(r"<[^>]+>", "", fragment)
    return _normalize_plain_text(html.unescape(text))


def _highlight_code_line(line):
    line = _escape_text(line)
    line = re.sub(
        r'\b(__int64|__fastcall|const|char|unsigned|return)\b',
        r'<span class="kw">\1</span>',
        line,
    )
    line = re.sub(r'\b(0x[0-9A-Fa-f]+|\d+LL|\d+)\b', r'<span class="num">\1</span>', line)
    line = re.sub(r'(&quot;[^&]*?&quot;)', r'<span class="str">\1</span>', line)
    return line


def _build_pseudocode_html(source, body_fragment, plain_text, truncated=False):
    source = _sanitize_comment(source or "clipboard")
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    func = _current_func_label()
    clean_func = re.sub(r"[^A-Za-z0-9_]", "_", func) or "sub_401000"
    src_string = _sanitize_string(source)
    loaded_at = now.replace("-", "").replace(" ", "").replace(":", "")

    rows = []
    header_lines = [
        "__int64 __fastcall %s(__int64 a1, const char *a2)" % clean_func,
        "{",
        "  const char *source = \"%s\";" % src_string,
        "  const char *mode = \"review_notes\";",
        "  unsigned __int64 loaded_at = 0x%sULL;" % loaded_at,
        "",
    ]
    for line in header_lines:
        rows.append('<div class="code">%s</div>' % _highlight_code_line(line))

    rendered = 0
    for idx, raw in enumerate(body_fragment.splitlines(), 1):
        raw = _sanitize_comment(raw.rstrip())
        prefix = "%04d" % idx
        rows.append(
            '<div><span class="comment">  // %s: </span><span class="body">%s</span></div>'
            % (prefix, raw)
        )
        rendered += 1
        if rendered >= MAX_RENDERED_LINES:
            rows.append('<div><span class="comment">  // ....: output clipped after 4000 rendered lines</span></div>')
            truncated = True
            break

    if truncated:
        rows.extend([
            '<div class="blank">&nbsp;</div>',
            '<div><span class="comment">  // note: input was truncated for responsiveness</span></div>',
        ])

    footer_lines = [
        "",
        "  return %dLL;" % min(len(plain_text or ""), 0x7FFFFFFF),
        "}",
    ]
    for line in footer_lines:
        rows.append('<div class="code">%s</div>' % _highlight_code_line(line))

    return """<!doctype html>
<html>
<head>
<meta charset="utf-8">
<style>
body {
  margin: 0;
  background: #fbfbfb;
  color: #24292e;
  font-family: Menlo, Consolas, Monaco, monospace;
  font-size: 11pt;
}
.wrap {
  padding: 8px 10px 18px 10px;
  white-space: pre-wrap;
}
.code {
  color: #24292e;
}
.comment {
  color: #6a737d;
  font-style: italic;
}
.body {
  color: #24292e;
}
.body-heading {
  color: #005cc5;
  font-weight: 600;
}
.kw {
  color: #005cc5;
  font-weight: 600;
}
.num {
  color: #6f42c1;
}
.str {
  color: #032f62;
}
a {
  color: #0366d6;
  text-decoration: none;
}
a:hover {
  text-decoration: underline;
}
::selection {
  background: #c8e1ff;
}
</style>
</head>
<body><div class="wrap">%s</div></body>
</html>""" % "\n".join(rows)


class MoyuForm(ida_kernwin.PluginForm):
    def __init__(self):
        ida_kernwin.PluginForm.__init__(self)
        self.parent = None
        self.editor = None
        self.source_edit = None
        self.status = None
        self.toolbar = None
        self.last_real_source = ""
        self.last_display_source = ""
        self.last_source_kind = ""
        self.last_plain_text = ""
        self.last_fragment = ""

    def OnCreate(self, form):
        try:
            self.parent = self.FormToPyQtWidget(form)
            self._build_ui()
            self._set_document("about:blank", "about:blank", _text_to_fragment(self._welcome_text()), self._welcome_text(), False)
        except Exception:
            ida_kernwin.warning("ida_moyu UI error:\n%s" % traceback.format_exc())

    def OnClose(self, form):
        global _FORM
        _FORM = None

    def _build_ui(self):
        QtCore, QtGui, QtWidgets = _qt()

        layout = QtWidgets.QVBoxLayout(self.parent)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.toolbar = QtWidgets.QFrame(self.parent)
        self.toolbar.setObjectName("moyuToolbar")
        bar = QtWidgets.QHBoxLayout(self.toolbar)
        bar.setContentsMargins(6, 4, 6, 4)
        bar.setSpacing(4)

        self.source_edit = QtWidgets.QLineEdit(self.toolbar)
        self.source_edit.setPlaceholderText("URL, local file path, or text")
        self.source_edit.returnPressed.connect(self._load_from_bar)
        bar.addWidget(self.source_edit, 1)

        load_btn = QtWidgets.QPushButton("Load", self.toolbar)
        load_btn.clicked.connect(self._load_from_bar)
        bar.addWidget(load_btn)

        file_btn = QtWidgets.QPushButton("File", self.toolbar)
        file_btn.clicked.connect(self._load_file_dialog)
        bar.addWidget(file_btn)

        clip_btn = QtWidgets.QPushButton("Clip", self.toolbar)
        clip_btn.clicked.connect(self._load_clipboard)
        bar.addWidget(clip_btn)

        find_btn = QtWidgets.QPushButton("Find", self.toolbar)
        find_btn.clicked.connect(self._find_text)
        bar.addWidget(find_btn)

        hide_btn = QtWidgets.QPushButton("Hide", self.toolbar)
        hide_btn.clicked.connect(self._toggle_toolbar)
        bar.addWidget(hide_btn)

        layout.addWidget(self.toolbar)

        self.editor = QtWidgets.QTextBrowser(self.parent)
        self.editor.setReadOnly(True)
        self.editor.setOpenLinks(False)
        self.editor.setOpenExternalLinks(False)
        self.editor.anchorClicked.connect(self._open_anchor)
        self.editor.setStyleSheet(
            "QTextBrowser {"
            " background: #fbfbfb;"
            " color: #24292e;"
            " border: 0;"
            " selection-background-color: #c8e1ff;"
            "}"
        )
        layout.addWidget(self.editor, 1)

        self.status = QtWidgets.QLabel(self.parent)
        self.status.setText("Ready")
        self.status.setStyleSheet("QLabel { padding: 3px 6px; color: #586069; background: #f6f8fa; }")
        layout.addWidget(self.status)

        self.toolbar.setStyleSheet(
            "QFrame#moyuToolbar { background: #f6f8fa; border-bottom: 1px solid #d0d7de; }"
            "QLineEdit { padding: 3px 6px; }"
            "QPushButton { padding: 3px 8px; }"
        )

        self._shortcut("Ctrl+L", self.source_edit.setFocus)
        self._shortcut("Ctrl+R", self._reload)
        self._shortcut("Ctrl+F", self._find_text)
        self._shortcut("Ctrl+Alt+H", self._toggle_toolbar)

    def _shortcut(self, seq, callback):
        QtCore, QtGui, QtWidgets = _qt()
        shortcut_cls = getattr(QtWidgets, "QShortcut", None)
        if shortcut_cls is None:
            shortcut_cls = QtGui.QShortcut
        shortcut = shortcut_cls(QtGui.QKeySequence(seq), self.parent)
        shortcut.activated.connect(callback)

    def _welcome_text(self):
        return "\n".join([
            "ida_moyu",
            "",
            "Input examples:",
            "  https://example.com/article.html",
            "  /tmp/notes.txt",
            "  paste raw text and press Load",
            "",
            "Shortcuts:",
            "  Ctrl+L       focus source bar",
            "  Ctrl+R       reload current source",
            "  Ctrl+F       find text",
            "  Ctrl+Alt+H   hide/show toolbar",
        ])

    def _set_status(self, text):
        if self.status:
            self.status.setText(text)

    def _set_document(self, real_source, display_source, fragment, plain_text, truncated=False, source_kind="inline"):
        self.last_real_source = real_source
        self.last_display_source = display_source
        self.last_source_kind = source_kind
        self.last_fragment = fragment
        self.last_plain_text = plain_text

        pseudo_html = _build_pseudocode_html(display_source, fragment, plain_text, truncated)
        self.editor.setHtml(pseudo_html)
        self.editor.moveCursor(_text_cursor_start())
        self._set_status("Loaded %d chars from %s" % (len(plain_text or ""), display_source))

    def _load_from_bar(self):
        value = self.source_edit.text().strip()
        if not value:
            return
        if self.last_source_kind == "url" and value == self.last_display_source:
            value = self.last_real_source
        self._load_value(value)

    def _load_value(self, value):
        try:
            expanded = os.path.expanduser(value)
            if _is_url(value):
                self._load_url(value)
            elif _is_file_url(value):
                self._load_file(_file_url_to_path(value))
            elif os.path.isfile(expanded):
                self._load_file(expanded)
            else:
                fragment = _text_to_fragment(value)
                plain = _fragment_to_plain_text(fragment)
                self.source_edit.setText("inline")
                self._set_document("inline", "inline", fragment, plain, False, "inline")
        except URLError as exc:
            ida_kernwin.warning("URL load failed:\n%s" % exc)
            self._set_status("URL load failed")
        except Exception:
            ida_kernwin.warning("Load failed:\n%s" % traceback.format_exc())
            self._set_status("Load failed")

    def _load_url(self, url):
        display_source = _fake_source_label()
        self.source_edit.setText(display_source)
        self._set_status("Fetching %s ..." % display_source)
        data, content_type, final_source, truncated = _fetch_url(url)
        text = _decode_bytes(data, content_type)
        if _looks_like_html(text, content_type):
            fragment, plain = _html_to_fragment(text, final_source)
        else:
            fragment = _text_to_fragment(text)
            plain = _fragment_to_plain_text(fragment)
        self.source_edit.setText(display_source)
        self._set_document(final_source, display_source, fragment, plain, truncated, "url")

    def _load_file(self, path):
        data, content_type, final_source, truncated = _read_local_file(path)
        text = _decode_bytes(data, content_type)
        if _looks_like_html(text, content_type):
            fragment, plain = _html_to_fragment(text, _path_to_file_url(final_source))
        else:
            fragment = _text_to_fragment(text)
            plain = _fragment_to_plain_text(fragment)
        self.source_edit.setText(final_source)
        self._set_document(final_source, final_source, fragment, plain, truncated, "file")

    def _open_anchor(self, qurl):
        try:
            url = qurl.toString()
        except Exception:
            url = str(qurl)
        if not url:
            return
        if url.startswith("#"):
            return
        self._load_value(url)

    def _load_file_dialog(self):
        QtCore, QtGui, QtWidgets = _qt()
        path, _selected = QtWidgets.QFileDialog.getOpenFileName(
            self.parent,
            "Open text or HTML",
            os.path.expanduser("~"),
            "Text and HTML (*.txt *.md *.log *.html *.htm *.c *.cpp *.h *.py);;All files (*)",
        )
        if path:
            self.source_edit.setText(path)
            self._load_value(path)

    def _load_clipboard(self):
        QtCore, QtGui, QtWidgets = _qt()
        text = QtWidgets.QApplication.clipboard().text()
        if not text:
            self._set_status("Clipboard is empty")
            return
        fragment = _text_to_fragment(text)
        plain = _fragment_to_plain_text(fragment)
        self.source_edit.setText("clipboard")
        self._set_document("clipboard", "clipboard", fragment, plain, False, "clipboard")

    def _reload(self):
        if self.last_source_kind in ("url", "file") and self.last_real_source:
            self._load_value(self.last_real_source)
        elif self.last_source_kind == "clipboard":
            self._load_clipboard()
        else:
            value = self.source_edit.text().strip()
            if value:
                self._load_value(value)

    def _find_text(self):
        QtCore, QtGui, QtWidgets = _qt()
        needle, ok = QtWidgets.QInputDialog.getText(self.parent, "Find", "Text:")
        if not ok or not needle:
            return
        if not self.editor.find(needle):
            cursor = self.editor.textCursor()
            cursor.movePosition(_text_cursor_start())
            self.editor.setTextCursor(cursor)
            if not self.editor.find(needle):
                self._set_status("Not found: %s" % needle)

    def _toggle_toolbar(self):
        visible = self.toolbar.isVisible()
        self.toolbar.setVisible(not visible)
        self._set_status("Toolbar %s" % ("hidden" if visible else "shown"))


class OpenMoyuAction(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        open_moyu_form()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


def open_moyu_form():
    global _FORM
    if _FORM is None:
        _FORM = MoyuForm()
        options = 0
        options |= getattr(ida_kernwin.PluginForm, "WOPN_TAB", 0)
        options |= getattr(ida_kernwin.PluginForm, "WOPN_RESTORE", 0)
        _FORM.Show(_plugin_title(), options=options)
    else:
        _FORM.Show(_plugin_title())
    return _FORM


class MoyuPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Read text and webpages in a pseudocode-styled IDA tab"
    help = "Open a dockable pseudocode-styled reader for text, local files, and URLs"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = "Ctrl+Alt+M"

    def init(self):
        try:
            desc = ida_kernwin.action_desc_t(
                ACTION_OPEN,
                PLUGIN_NAME,
                OpenMoyuAction(),
                "Ctrl+Alt+M",
                "Open ida_moyu",
                -1,
            )
            ida_kernwin.register_action(desc)
            ida_kernwin.attach_action_to_menu("Edit/Plugins/", ACTION_OPEN, ida_kernwin.SETMENU_APP)
        except Exception:
            pass
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        open_moyu_form()

    def term(self):
        try:
            ida_kernwin.detach_action_from_menu("Edit/Plugins/", ACTION_OPEN)
            ida_kernwin.unregister_action(ACTION_OPEN)
        except Exception:
            pass


def PLUGIN_ENTRY():
    return MoyuPlugin()
