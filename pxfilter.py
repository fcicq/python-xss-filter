# -*- coding: utf-8 -*-
"""
Python 富文本XSS过滤类
@package XssHtml
@version 0.1
@link http://phith0n.github.io/python-xss-filter
@since 20150407
@copyright (c) Phithon All Rights Reserved

Based on native Python module HTMLParser purifier of HTML, To Clear all javascript in html
You can use it in all python web framework
Written by Phithon <root@leavesongs.com> in 2015 and placed in the public domain.
phithon <root@leavesongs.com> 编写于20150407
From: XDSEC <www.xdsec.org> & 离别歌 <www.leavesongs.com>
GitHub Pages: https://github.com/phith0n/python-xss-filter
Usage:
	parser = XssHtml()
	parser.feed('<html code>')
	parser.close()
	html = parser.getHtml()
	print html

Requirements
Python 2.6+ or 3.2+
Cannot defense xss in browser which is belowed IE7
浏览器版本：IE7+ 或其他浏览器，无法防御IE6及以下版本浏览器中的XSS
"""
import re
try:
	from html.parser import HTMLParser
except ImportError:
	from HTMLParser import HTMLParser

_SET_TRUE_FALSE = set(["true", "false"])
_NODE_A_LIMIT = {"target": set(["_blank", "_self"])}
_NODE_EMBED_LIMIT = {
        "type": set(["application/x-shockwave-flash"]),
        "wmode": set(["transparent", "window", "opaque"]),
        "play": _SET_TRUE_FALSE,
        "loop": _SET_TRUE_FALSE,
        "menu": _SET_TRUE_FALSE,
        "allowfullscreen": _SET_TRUE_FALSE,
}
_TRUE_URL_RE = re.compile(r"^(http|https|ftp)://.+", re.I | re.S)
_TRUE_STYLE_RE_1 = re.compile(r"(\\|&#|/\*|\*/)")
_TRUE_STYLE_RE_2 = re.compile(r"e.*x.*p.*r.*e.*s.*s.*i.*o.*n")
class XssHtml(HTMLParser):
	allow_tags = set(['a', 'img', 'br', 'strong', 'b', 'code', 'pre',
				  'p', 'div', 'em', 'span', 'h1', 'h2', 'h3', 'h4',
				  'h5', 'h6', 'blockquote', 'ul', 'ol', 'tr', 'th', 'td',
				  'hr', 'li', 'u', 'embed', 's', 'table', 'thead', 'tbody',
				  'caption', 'small', 'q', 'sup', 'sub'])
	common_attrs = set(["id", "style", "class", "name"])
	nonend_tags = set(["img", "hr", "br", "embed"])
	tags_own_attrs = {
		"img": set(["src", "width", "height", "alt", "align"]),
		"a": set(["href", "target", "rel", "title"]),
		"embed": set(["src", "width", "height", "type", "allowfullscreen", "loop", "play", "wmode", "menu"]),
		"table": set(["border", "cellpadding", "cellspacing"]),
	}

	def __init__(self, allows=None):
		HTMLParser.__init__(self)
		self.allow_tags = allows if allows else self.allow_tags
		self.result = []
		self.start = []
		self.data = []

	def getHtml(self):
		"""
		Get the safe html code
		"""
                tmp = map(lambda i: self.result[i].strip('\n'), range(0, len(self.result)))
                return ''.join(tmp)

	def handle_startendtag(self, tag, attrs):
		self.handle_starttag(tag, attrs)

	def handle_starttag(self, tag, attrs):
		if tag not in self.allow_tags:
			return
		end_diagonal = ' /' if tag in self.nonend_tags else ''
		if not end_diagonal:
			self.start.append(tag)
		attdict = {}
		for attr in attrs:
			attdict[attr[0]] = attr[1]

		attdict = self.__wash_attr(attdict, tag)
		if hasattr(self, "node_%s" % tag):
			attdict = getattr(self, "node_%s" % tag)(attdict)
		else:
			attdict = self.node_default(attdict)

		attrs = []
		for (key, value) in attdict.items():
			attrs.append('%s="%s"' % (key, self.__htmlspecialchars(value)))
		attrs = (' ' + ' '.join(attrs)) if attrs else ''
		self.result.append('<' + tag + attrs + end_diagonal + '>')

	def handle_endtag(self, tag):
		if self.start and tag == self.start[len(self.start) - 1]:
			self.result.append('</' + tag + '>')
			self.start.pop()

	def handle_data(self, data):
		self.result.append(self.__htmlspecialchars(data))

	def handle_entityref(self, name):
		if name.isalpha():
			self.result.append("&%s;" % name)

	def handle_charref(self, name):
		if name.isdigit():
			self.result.append("&#%s;" % name)

	def node_default(self, attrs):
		attrs = self.__common_attr(attrs)
		return attrs

	def node_img(self, attrs):
		attrs = self.__common_attr(attrs)
		attrs = self.__get_link(attrs, "src")
		return attrs

	def node_a(self, attrs):
		attrs = self.__common_attr(attrs)
		attrs = self.__get_link(attrs, "href")
		attrs = self.__set_attr_default(attrs, "target", "_blank")
		attrs = self.__limit_attr(attrs, _NODE_A_LIMIT)
		return attrs

	def node_embed(self, attrs):
		attrs = self.__common_attr(attrs)
		attrs = self.__get_link(attrs, "src")
		attrs = self.__limit_attr(attrs, _NODE_EMBED_LIMIT)
		attrs["allowscriptaccess"] = "never"
		attrs["allownetworking"] = "none"
		return attrs

	def __true_url(self, url):
		if _TRUE_URL_RE.match(url):
			return url
		else:
			return "http://%s" % url

	def __true_style(self, style):
		if style:
			style = _TRUE_STYLE_RE_1.sub("_", style)
			style = _TRUE_STYLE_RE_2.sub("_", style)
		return style

	def __get_style(self, attrs):
		if "style" in attrs:
			attrs["style"] = self.__true_style(attrs.get("style"))
		return attrs

	def __get_link(self, attrs, name):
		if name in attrs:
			attrs[name] = self.__true_url(attrs[name])
		return attrs

	def __wash_attr(self, attrs, tag):
		if tag in self.tags_own_attrs:
			other = self.tags_own_attrs.get(tag)
		else:
			other = []
		if attrs:
			for (key, value) in attrs.items():
				if key not in self.common_attrs and key not in other:
					del attrs[key]
		return attrs

	def __common_attr(self, attrs):
		attrs = self.__get_style(attrs)
		return attrs

	def __set_attr_default(self, attrs, name, default = ''):
		if name not in attrs:
			attrs[name] = default
		return attrs

	def __limit_attr(self, attrs, limit = {}):
		for (key, value) in limit.items():
			if key in attrs and attrs[key] not in value:
				del attrs[key]
		return attrs

	def __htmlspecialchars(self, html):
		return html.replace("<", "&lt;")\
			.replace(">", "&gt;")\
			.replace('"', "&quot;")\
			.replace("'", "&#039;")


if "__main__" == __name__:
	parser = XssHtml()
	parser.feed("""<p><img src=1 onerror=alert(/xss/)></p><div class="left">
		<a href='javascript:prompt(1)'><br />hehe</a></div>
		<p id="test" onmouseover="alert(1)">&gt;M<svg>
		<a href="https://www.baidu.com" target="self">MM</a></p>
		<embed src='javascript:alert(/hehe/)' allowscriptaccess=always />""")
	parser.close()
	print(parser.getHtml())