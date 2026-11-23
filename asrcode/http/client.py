"""ASR HTTP authentication and device request client; no GUI dependencies."""
import hashlib,json,random,re,time
import urllib.request
import urllib.error
DEFAULT_IP="192.168.100.1"
DEFAULT_USER="admin"
DEFAULT_PWD="admin"
def md5(s):
    return hashlib.md5(s.encode("utf-8")).hexdigest()


class AsrHttp:
    """设备 Web 后端客户端 (Digest 认证, nonce 动态获取, 自动重登录, 节流)"""

    DEFAULT_REALM = "Highwmg"
    DEFAULT_NONCE = "5804"
    # ★ 摘要认证里参与哈希的 uri 必须是 "/cgi/xml_action.cgi"（和前端 getAuthHeader() 一致），
    #   但实际请求的物理路径是 "/xml_action.cgi"（没有 /cgi 前缀）。两者不同，
    #   写错会得到 "HTTP 500，reason=OK" 这种自相矛盾的响应。
    URI = "/cgi/xml_action.cgi"
    MIN_INTERVAL = 0.6          # NZ_SSG_V20 实测 <0.6s 会偶发 500 / 连接被关闭

    def __init__(self, ip=DEFAULT_IP, user=DEFAULT_USER, pwd=DEFAULT_PWD, log=print):
        self.base = "http://" + str(ip).strip().replace("http://", "").rstrip("/")
        self.user = user or DEFAULT_USER
        self.pwd = pwd or DEFAULT_PWD
        self.log = log
        self.realm = self.DEFAULT_REALM
        self.qop = "auth"
        self.nonce = self.DEFAULT_NONCE
        self.ha1 = md5("%s:%s:%s" % (self.user, self.realm, self.pwd))
        self.nc = 1
        self.logged = False
        self._last = 0.0
        # 设备是局域网直连，必须绕过系统代理，否则请求会被代理服务器吞掉
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    # ---------- 基础 ----------
    def _throttle(self, gap=None):
        gap = gap or self.MIN_INTERVAL
        dt = time.time() - self._last
        if dt < gap:
            time.sleep(gap - dt)
        self._last = time.time()

    @staticmethod
    def _parse_auth(header, cur=None):
        d = dict(cur or {})
        if not header:
            return d
        for k in ("realm", "nonce", "qop", "nextnonce", "opaque"):
            m = re.search(k + r'="?([^",]+)"?', header, re.I)
            if m:
                d[k] = m.group(1)
        return d

    def _cnonce(self):
        return md5(str(random.randint(0, 100001)) + str(int(time.time() * 1000)))[:16]

    def _probe(self):
        """GET /login.cgi 拿动态 nonce"""
        self._throttle()
        try:
            r = self.opener.open(urllib.request.Request(
                self.base + "/login.cgi", headers={"Accept": "*/*"}), timeout=8)
            info = self._parse_auth(r.headers.get("WWW-Authenticate"),
                                    {"realm": self.DEFAULT_REALM,
                                     "nonce": self.DEFAULT_NONCE, "qop": "auth"})
            r.close()
            return info
        except urllib.error.HTTPError as e:
            return self._parse_auth(e.headers.get("WWW-Authenticate"),
                                    {"realm": self.DEFAULT_REALM,
                                     "nonce": self.DEFAULT_NONCE, "qop": "auth"})
        except Exception as e:
            self.log("        /login.cgi 探测异常: %r" % e)
            return None

    # ---------- 登录 ----------
    def login(self):
        info = self._probe()
        if info:
            self.realm = info.get("realm", self.DEFAULT_REALM)
            self.nonce = info.get("nextnonce") or info.get("nonce") or self.DEFAULT_NONCE
            self.qop = info.get("qop", "auth")
        self.ha1 = md5("%s:%s:%s" % (self.user, self.realm, self.pwd))

        # URL 参数里的 response 用 /cgi/protected.cgi
        ha2_url = md5("GET:/cgi/protected.cgi")
        # 设备上必须要同时带 Digest 头，HA2 用 /cgi/xml_action.cgi
        # 只发 URL 参数的话返回 200 但不会建立会话，后续请求一律 UNAUTHORIZED
        ha2_hdr = md5("GET:/cgi/xml_action.cgi")
        c = self._cnonce()
        resp_url = md5("%s:%s:00000001:%s:%s:%s" % (self.ha1, self.nonce, c, self.qop, ha2_url))
        resp_hdr = md5("%s:%s:00000001:%s:%s:%s" % (self.ha1, self.nonce, c, self.qop, ha2_hdr))
        url = ("%s/login.cgi?Action=Digest&username=%s&realm=%s&nonce=%s&response=%s"
               "&qop=%s&cnonce=%s&temp=asr"
               % (self.base, self.user, self.realm, self.nonce, resp_url, c, self.qop))
        auth = ('Digest username="%s", realm="%s", nonce="%s", uri="%s", '
                'response="%s", qop=%s, nc=00000001, cnonce="%s"'
                % (self.user, self.realm, self.nonce, self.URI, resp_hdr, self.qop, c))
        self._throttle()
        try:
            r = self.opener.open(urllib.request.Request(
                url, headers={"Authorization": auth, "Accept": "*/*"}), timeout=10)
            st, body, head = r.status, r.read().decode("utf-8", "ignore"), r.headers
            r.close()
        except urllib.error.HTTPError as e:
            st, body, head = e.code, e.read().decode("utf-8", "ignore"), e.headers
        except Exception as e:
            st, body, head = 0, str(e), None

        nx = self._parse_auth(head.get("WWW-Authenticate") if head else None)
        if nx.get("nextnonce"):
            self.nonce = nx["nextnonce"]
        elif nx.get("nonce"):
            self.nonce = nx["nonce"]
        self.nc = 2                       # 登录已消耗 00000001
        ok = (st == 200) and (("200 OK" in body) if body.strip() else True)
        self.logged = ok
        self.log("[登录] %s @ %s  HTTP %s  nonce=%s  -> %s"
                 % (self.user, self.base, st, self.nonce, "成功" if ok else "失败"))
        if not ok and body:
            self.log("       响应: %s" % body[:300].replace("\r\n", " "))
        return ok

    # ---------- 业务请求 ----------
    def _auth(self, method):
        ha2 = md5("%s:%s" % (method.upper(), self.URI))
        c = self._cnonce()
        nc = "%08X" % self.nc
        self.nc += 1
        resp = md5("%s:%s:%s:%s:%s:%s" % (self.ha1, self.nonce, nc, c, self.qop, ha2))
        return ('Digest username="%s", realm="%s", nonce="%s", uri="%s", '
                'response="%s", qop=%s, nc=%s, cnonce="%s"'
                % (self.user, self.realm, self.nonce, self.URI, resp, self.qop, nc, c))

    def _send(self, method, file, xml=None):
        m = "set" if xml else "get"
        url = "%s/xml_action.cgi?method=%s&module=duster&file=%s" % (self.base, m, file)
        hdr = {"Authorization": self._auth(method),
               "Pragma": "no-cache",
               "X-Requested-With": "XMLHttpRequest",
               "Accept": "*/*"}
        data = None
        if xml:
            hdr["Content-Type"] = "application/xml"
            data = xml.encode("utf-8")
        self._throttle()
        req = urllib.request.Request(url, data=data,
                                     method=("POST" if xml else "GET"), headers=hdr)
        try:
            r = self.opener.open(req, timeout=15)
            return r.status, r.read().decode("utf-8", "ignore")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "ignore")
        except Exception as e:
            return 0, str(e)

    # ---------- JSON 通道（LB12A_N12 / PXA1803 新固件）----------
    # 老固件：xml_action.cgi?method=get|set&module=duster&file=<name>   传/回 XML
    # 新固件：xml_action.cgi?method=get|post&module=duster&file=json_<name>  传/回 JSON
    #   注意两点：① file 要带 json_ 前缀 ② 写用的是小写 post，不是老接口的 set
    #   响应形如 {"result":"success"}
    def _send_json(self, name, obj=None):
        m = "post" if obj is not None else "get"
        url = ("%s/xml_action.cgi?method=%s&module=duster&file=json_%s"
               % (self.base, m, name))
        hdr = {"Authorization": self._auth("POST" if obj is not None else "GET"),
               "Pragma": "no-cache",
               "X-Requested-With": "XMLHttpRequest",
               "Accept": "*/*"}
        data = None
        if obj is not None:
            hdr["Content-Type"] = "application/json"
            data = json.dumps(obj, ensure_ascii=False,
                              separators=(",", ":")).encode("utf-8")
        self._throttle()
        req = urllib.request.Request(
            url, data=data, method=("POST" if obj is not None else "GET"),
            headers=hdr)
        try:
            r = self.opener.open(req, timeout=15)
            return r.status, r.read().decode("utf-8", "ignore")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "ignore")
        except Exception as e:
            return 0, str(e)

    def request_json(self, name, obj=None, relogin=True):
        st, body = self._send_json(name, obj)
        if relogin and (st == 401 or st == 0 or "UNAUTHORIZED" in (body or "")):
            self.log("       会话失效，重新登录后重试 ...")
            if self.login():
                st, body = self._send_json(name, obj)
        return st, body or ""

    def get_json(self, name):
        return self.request_json(name, None)

    def post_json(self, name, obj):
        return self.request_json(name, obj)

    def request(self, file, xml=None, relogin=True):
        st, body = self._send("POST" if xml else "GET", file, xml)
        if relogin and (st == 401 or st == 0 or "UNAUTHORIZED" in (body or "")):
            self.log("       会话失效，重新登录后重试 ...")
            if self.login():
                st, body = self._send("POST" if xml else "GET", file, xml)
        return st, body or ""

    # 这些 file 名是「动作」而不是「查询」：一访问就真执行。
    # 教训：restore_defaults 曾被当成普通接口盲 GET，结果整台设备配置被清空。
    DESTRUCTIVE_FILES = frozenset(
        ("restore_defaults", "power_off", "reboot", "reset", "factory"))

    def get(self, file, allow_destructive=False):
        if file in self.DESTRUCTIVE_FILES and not allow_destructive:
            raise ValueError(
                "拒绝 GET file=%s：它是「动作」不是「查询接口」，"
                "一访问就会真的执行（关机/重启/恢复出厂）。"
                "探测或读状态时不能碰它。" % file)
        return self.request(file, None)

    def post(self, file, xml):
        return self.request(file, xml)
