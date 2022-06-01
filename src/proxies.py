import random
from collections import defaultdict
from typing import List, Optional, Tuple

from aiohttp_socks import ProxyConnector
from yarl import URL

from .core import ONLY_MY_IP, PROXIES_URLS
from .dns_utils import resolve_all
from .system import fetch, read_or_fetch


# @formatter:off
_globals_before = set(globals().keys()).union({'_globals_before'})
# noinspection PyUnresolvedReferences
from .vendor.load_proxies import *
obtain_proxies = globals()[set(globals().keys()).difference(_globals_before).pop()]
# @formatter:on


INVALID_SCHEME_ERROR = "Invalid scheme component"
INVALID_PORT_ERROR = "Invalid port component"


def normalize_url(url: str) -> str:
    try:
        ProxyConnector.from_url(url)
        return url
    except ValueError as e:
        if INVALID_SCHEME_ERROR in str(e):
            return normalize_url(f"http://{url}")
        elif INVALID_PORT_ERROR in str(e) and url.count(":") == 4:
            url, username, password = url.rsplit(":", 2)
            return str(URL(url).with_user(username).with_password(password))
        else:
            raise ValueError("Proxy config parsing failed") from e


class ProxySet:

    def __init__(self, proxies_file: Optional[str] = None, skip_ratio: int = 0):
        self._proxies_file = proxies_file
        self._skip_ratio = skip_ratio
        self._loaded_proxies = []
        self._connections = defaultdict(int)

    @property
    def has_proxies(self) -> bool:
        return self._skip_ratio != ONLY_MY_IP

    async def reload(self) -> int:
        if not self.has_proxies:
            return 0

        if self._proxies_file:
            proxies = await load_provided_proxies(self._proxies_file)
        else:
            proxies = await load_system_proxies()

        if not proxies:
            return 0

        # resolve DNS entries in case proxy is given using hostname rather than IP
        urls = [URL(proxy_url) for proxy_url in proxies]
        ips = await resolve_all([url.host for url in urls])
        proxies = [str(url.with_host(ips.get(url.host, url.host))) for url in urls]
        self._loaded_proxies = proxies
        self._connections = defaultdict(int)
        return len(self._loaded_proxies)

    def pick_random(self) -> Optional[str]:
        if not self.has_proxies:
            return None
        if self._skip_ratio > 0 and random.random() * 100 <= self._skip_ratio:
            return None
        return random.choice(self._loaded_proxies)

    def pick_random_connector(self) -> Optional[ProxyConnector]:
        proxy_url = self.pick_random()
        return ProxyConnector.from_url(proxy_url, ssl=False) if proxy_url is not None else None

    def __len__(self) -> int:
        if not self.has_proxies:
            return 0
        return len(self._loaded_proxies)

    def track_alive(self, proxy_url: str) -> None:
        self._connections[proxy_url] += 1

    @property
    def alive(self) -> List[Tuple[int, str]]:
        return sorted([(v, k) for (k, v) in self._connections.items()], reverse=True)


class NoProxySet:
    alive = []

    @staticmethod
    def pick_random(self) -> Optional[str]:
        return None

    @staticmethod
    def pick_random_connector(self) -> Optional[ProxyConnector]:
        return None

    @staticmethod
    def has_proxies(self) -> bool:
        return False

    @staticmethod
    def track_alive(self, proxy_url: str) -> None:
        pass


async def load_provided_proxies(proxies_file: str) -> Optional[List[str]]:
    content = await read_or_fetch(proxies_file)
    proxies = list(map(normalize_url, content.split()))
    return proxies


async def load_system_proxies():
    raw = await fetch(random.choice(PROXIES_URLS))
    try:
        proxies = obtain_proxies(raw)
    except Exception:
        proxies = []
    proxies = list(map(normalize_url, proxies))
    return proxies
