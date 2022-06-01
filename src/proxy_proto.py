import asyncio
import io
from functools import lru_cache, partial
from ssl import SSLContext
from typing import BinaryIO, Callable, Optional, Tuple

from python_socks._proto import http as http_proto, socks4, socks5
from python_socks.async_.asyncio import Proxy
from python_socks.async_.asyncio._proxy import HttpProxy, Socks4Proxy, Socks5Proxy

from .core import logger


class ProxyProtocol(asyncio.Protocol):

    def __init__(
        self,
        proxy_url: str,  # XXX: is one is only used for the logging
        proxy: Proxy,
        loop: asyncio.AbstractEventLoop,
        on_close: asyncio.Future,
        dest: Tuple[str, int],
        ssl: Optional[SSLContext],
        downstream_factory: Callable[[], asyncio.Protocol],
        connect_timeout: int = 30,
        on_connect=None
    ):
        logger.debug(f"Factory called for {proxy_url}")
        self._loop = loop
        self._transport = None
        self._downstream_factory = downstream_factory
        self._downstream_protocol = None
        self._downstream_pause_writing = None
        self._downstream_resume_writing = None
        self._proxy_url = proxy_url
        self._proxy = proxy
        self._dest = dest
        self._ssl = ssl
        self._on_close = on_close
        self._on_close.add_done_callback(self._handle_cancellation)
        self._dest_connected = False
        self._dest_connect_timer = None
        self._dest_connect_timeout = connect_timeout
        self._on_connect = on_connect

    def connection_made(self, transport):
        logger.debug(f"Connected to {self._proxy_url}")
        assert self._transport is None
        self._transport = transport
        assert self._dest_connect_timer is None
        self._dest_connect_timer = self._loop.call_later(
            self._dest_connect_timeout, self._abort_connection)
        self._kickoff_negotiate()

    def _kickoff_negotiate(self):
        raise NotImplemented

    def connection_lost(self, exc):
        logger.debug(f"Disconnected from {self._proxy_url} {exc}")
        self._transport = None
        if self._downstream_protocol is not None:
            self._downstream_protocol.connection_lost(exc)
        if self._on_connect and not self._on_connect.done():
            self._on_connect.set_result(False)
        if self._on_close.done():
            return
        if exc is not None:
            self._on_close.set_exception(exc)
        else:
            self._on_close.set_result(None)

    def pause_writing(self):
        if self._downstream_pause_writing is not None:
            self._downstream_pause_writing()

    def resume_writing(self):
        if self._downstream_resume_writing is not None:
            self._downstream_resume_writing()

    def data_received(self, data):
        n_bytes = len(data)
        logger.debug(f"Receieved data from {self._proxy_url} {n_bytes} bytes")
        if self._dest_connected:
            self._downstream_protocol.data_received(data)
        else:
            try:
                self._negotiate_data_received(data)
            except Exception as exc:
                logger.debug(f"Processing failed for {self._proxy_url} with {exc}")
                if not self._on_close.done():
                    self._on_close.set_exception(exc)
                    self._transport.abort()

    def _negotiate_data_received(self, data):
        raise NotImplemented

    def eof_received(self):
        if self._downstream_protocol is not None:
            self._downstream_protocol.eof_received()

    def _handle_cancellation(self, on_close):
        if on_close.cancelled() and self._transport and not self._transport.is_closing:
            self._transport.abort()
            self._transport = None

    def _dest_connection_made(self):
        assert not self._dest_connected
        self._dest_connected = True
        self._downstream_protocol = self._downstream_factory()
        if hasattr(self._downstream_protocol, "pause_writing"):
            self._downstream_pause_writing = self._downstream_protocol.pause_writing
        if hasattr(self._downstream_protocol, "resume_writing"):
            self._downstream_resume_writing = self._downstream_protocol.resume_writing
        if self._ssl is None:
            self._cancel_dest_connect_timer()
            logger.debug(f"Dest is connected through {self._proxy_url}")
            self._downstream_protocol.connection_made(self._transport)
        else:
            _tls = self._loop.create_task(
                self._loop.start_tls(self._transport, self._downstream_protocol, self._ssl))
            _tls.add_done_callback(self._setup_downstream_tls)

    def _cancel_dest_connect_timer(self):
        if self._dest_connect_timer is not None:
            self._dest_connect_timer.cancel()
            self._dest_connect_timer = None

    def _setup_downstream_tls(self, task):
        self._cancel_dest_connect_timer()
        try:
            transport = task.result()
            if not self._transport:
                return
            if transport:
                self._downstream_protocol.connection_made(transport)
                logger.debug(f"Dest is connected through {self._proxy_url}")
            else:
                self._transport.abort()
        except Exception as exc:
            if not self._on_close.done():
                self._on_close.set_exception(exc)
                self._transport.abort()

    def _abort_connection(self):
        logger.debug(f"Response timeout for {self._proxy_url}")
        if not self._on_close.done():
            # XXX: most likely this should be timeout exception rather than None
            self._on_close.set_result(None)
        if self._transport is not None:
            self._transport.abort()
            self._transport = None


class ProxyError(IOError):
    pass


# XXX: this could be proper ABC
class Socks4Protocol(ProxyProtocol):

    def _kickoff_negotiate(self):
        self._dest_connect()

    def _negotiate_data_received(self, data):
        assert len(data) == 8, "SOCKS4: invalid response (wrong packet size)"
        # we are not validating addr, port pair
        if data[0] != socks4.RSV:
            raise ProxyError("SOCKS4: proxy server sent invalid data")
        status = ord(data[1:2])
        if status != socks4.ReplyCode.REQUEST_GRANTED:
            status_error = socks4.ReplyMessages.get(status, "Unknown error")
            raise ProxyError(f"SOCKS4: wrong status {status_error}")
        self._dest_connection_made()

    def _dest_connect(self):
        addr, port = self._dest
        req = socks4.ConnectRequest(host=addr, port=port, user_id='', rdns=False)
        req.set_resolved_host(addr)
        self._transport.write(bytes(req))


# XXX: netty's top-level performance trick: reuse pipeline and handler objects
#      curious if this can be done in Python efficiently
class Socks5Protocol(ProxyProtocol):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._auth_method_req = None
        self._auth_method = None
        self._auth_done = False
        self._auth_req_sent = False

    def _negotiate_data_received(self, data):
        n_bytes = len(data)
        if self._auth_done:
            # expecting connect response
            self._read_connect_response(data)
            self._dest_connection_made()
        elif self._auth_method_req and self._auth_method is None:
            # expecting auth method response
            assert n_bytes == 2, "SOCKS5: invalid auth method response (wrong packet size)"
            res = socks5.AuthMethodsResponse(data)
            res.validate(request=self._auth_method_req)
            self._auth_method = res.auth_method
            if self._auth_method == socks5.AuthMethod.USERNAME_PASSWORD:
                req = socks5.AuthRequest(
                    username=self._proxy._username,
                    password=self._proxy._password
                )
                self._transport.write(bytes(req))
                self._auth_req_sent = True
                logger.debug(f"Sent user/pass for {self._proxy_url}")
            else:
                self._auth_done = True
                logger.debug(f"Auth is ready for {self._proxy_url}")
                self._dest_connect()
        elif self._auth_method_req and self._auth_method is not None:
            # expecting auth response
            assert n_bytes == 2, "SOCKS5: invalid auth response (wrong packet size)"
            res = socks5.AuthResponse(data)
            res.validate()
            self._auth_done = True
            logger.debug(f"Auth is ready for {self._proxy_url}")
            self._dest_connect()
        else:
            raise ProxyError("SOCKS5: invalid state")

    def _read_exactly(self, buffer: BinaryIO, n: int) -> bytes:
        data = buffer.read(n)
        if len(data) < n:
            raise ProxyError("SOCKS5: invalid response (wrong packet size)")
        return data

    def _read_connect_response(self, data: bytes) -> None:
        buffer = io.BytesIO(data)
        (socks_ver, reply, rsv, addr_type) = self._read_exactly(buffer, 4)
        if socks_ver != socks5.SOCKS_VER:
            raise ProxyError("SOCKS5: unexpected version number")
        if reply != socks5.ReplyCode.GRANTED:
            error_message = socks5.ReplyMessages.get(reply, 'Unknown error')
            raise ProxyError(f"SOCKS5: invalid reply code {error_message}")
        if rsv != socks5.RSV:
            raise ProxyError("SOCKS5: invalid reserved byte")
        if addr_type == 0x01:
            self._read_exactly(buffer, 4)
        elif addr_type == 0x03:
            length = self._read_exactly(buffer, 1)
            self._read_exactly(buffer, ord(length))
        elif addr_type == 0x04:
            self._read_exactly(buffer, 16)
        else:
            raise ProxyError("SOCKS5: proxy server sent invalid data")
        self._read_exactly(buffer, 2)
        if buffer.read(1):
            raise ProxyError("SOCKS5: invalid response (excessive data)")

    def _kickoff_negotiate(self):
        self._request_auth_methods()

    def _request_auth_methods(self):
        assert self._auth_method_req is None
        self._auth_method_req = socks5.AuthMethodsRequest(
            username=self._proxy._username,
            password=self._proxy._password,
        )
        self._transport.write(bytes(self._auth_method_req))
        logger.debug(f"Sent auth methods req to {self._proxy_url}")

    def _dest_connect(self):
        assert not self._dest_connected
        addr, port = self._dest
        req = socks5.ConnectRequest(host=addr, port=port, rdns=False)
        req.set_resolved_host(addr)
        self._transport.write(bytes(req))
        logger.debug(f"Sent connection req to {self._proxy_url}")


class HttpTunelProtocol(ProxyProtocol):

    def _kickoff_negotiate(self):
        self._dest_connect()

    def _negotiate_data_received(self, data):
        status_line = io.BytesIO(data).readline().decode("utf-8", "surrogateescape")

        if not status_line:
            raise ProxyError("HTTP: connection closed unexpectedly")

        status_line = status_line.rstrip()
        try:
            proto, status_code, status_msg = status_line.split(" ", 2)
        except ValueError:
            raise ProxyError("HTTP: proxy server sent invalid response")

        if not proto.startswith("HTTP/"):
            raise ProxyError("HTTP: proxy server does not appear to be an HTTP proxy")

        try:
            status_code = int(status_code)
        except ValueError:
            raise ProxyError("HTTP: proxy server did not return a valid HTTP status")

        if status_code not in {200, 201, 204}:
            raise ProxyError(f"HTTP: proxy server sent non-200 HTTP status {status_line}")

        self._dest_connection_made()

    def _dest_connect(self):
        addr, port = self._dest
        # XXX: remove user agent field?
        req = http_proto.ConnectRequest(
            host=addr, port=port,
            login=self._proxy._username,
            password=self._proxy._password
        )
        self._transport.write(bytes(req))


_CONNECTORS = {
    Socks4Proxy: Socks4Protocol,
    Socks5Proxy: Socks5Protocol,
    HttpProxy: HttpTunelProtocol,
}


@lru_cache(maxsize=4096)
def for_proxy(proxy_url: str) -> Tuple[Proxy, Callable[[], asyncio.Protocol]]:
    proxy = Proxy.from_url(proxy_url)
    proxy_protocol = _CONNECTORS[type(proxy)]
    return proxy, partial(proxy_protocol, proxy_url, proxy)
