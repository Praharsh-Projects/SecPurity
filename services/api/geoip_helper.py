import os
from typing import Optional, Dict, Any
from contextlib import suppress

try:
    from geoip2.database import Reader
except Exception:
    Reader = None  # geoip disabled or not installed


class GeoIP:
    """
    Tiny wrapper around MaxMind readers.
    - Lazy open
    - Safe no-op when disabled or file missing
    - Thread-safe reads (Reader is thread-safe for lookups)
    """

    def __init__(self, enabled: bool, city_path: Optional[str], asn_path: Optional[str]):
        self.enabled = bool(enabled and Reader)
        self.city_path = city_path
        self.asn_path = asn_path
        self._city = None
        self._asn = None

    @classmethod
    def from_env(cls) -> "GeoIP":
        enabled = os.getenv("GEOIP_ENABLED", "false").lower() == "true"
        return cls(
            enabled=enabled,
            city_path=os.getenv("MAXMIND_CITY_DB"),
            asn_path=os.getenv("MAXMIND_ASN_DB"),
        )

    def _open(self):
        if not self.enabled:
            return
        if not self._city and self.city_path and os.path.exists(self.city_path):
            self._city = Reader(self.city_path)
        if not self._asn and self.asn_path and os.path.exists(self.asn_path):
            self._asn = Reader(self.asn_path)

    def annotate(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich event in-place with src/dst geo (country, city, ASN, org) if present.
        Expects IPv4/IPv6 in event['src_ip'] and event['dst_ip'].
        """
        if not self.enabled:
            return event

        self._open()
        if not (self._city or self._asn):
            return event

        def _one(ip_key: str, prefix: str):
            ip = event.get(ip_key)
            if not ip:
                return
            # City info
            if self._city:
                with suppress(Exception):
                    r = self._city.city(ip)
                    event[f"{prefix}_country"] = r.country.iso_code or None
                    event[f"{prefix}_city"] = (r.city.name or None)
                    event[f"{prefix}_lat"] = r.location.latitude
                    event[f"{prefix}_lon"] = r.location.longitude
            # ASN info
            if self._asn:
                with suppress(Exception):
                    r = self._asn.asn(ip)
                    event[f"{prefix}_asn"] = r.autonomous_system_number
                    event[f"{prefix}_org"] = r.autonomous_system_organization

        _one("src_ip", "src")
        _one("dst_ip", "dst")
        return event

    def info(self) -> Dict[str, Any]:
        return {
            "enabled": self.enabled,
            "city_loaded": bool(self._city),
            "asn_loaded": bool(self._asn),
            "city_path": self.city_path,
            "asn_path": self.asn_path,
        }

    def close(self):
        with suppress(Exception):
            if self._city:
                self._city.close()
            if self._asn:
                self._asn.close()
        self._city = None
        self._asn = None