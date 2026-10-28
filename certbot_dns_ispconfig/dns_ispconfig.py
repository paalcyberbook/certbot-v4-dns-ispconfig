"""DNS Authenticator for ISPConfig."""
""" Modifications by Paal A. Bergsmark <paal@kunnskap.no> supporting Certbot v4.2+ """

import json
import logging
import time

import requests

from certbot import errors
from certbot.plugins import dns_common

logger = logging.getLogger(__name__)


class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for ISPConfig

    This Authenticator uses the ISPConfig Remote REST API to fulfill a dns-01 challenge.
    """
    description = "Obtain certificates using a DNS TXT record (if you are using ISPConfig for DNS)."
    ttl = 60

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super(Authenticator, cls).add_parser_arguments(
            add, default_propagation_seconds=120
        )
        add("credentials", help="ISPConfig credentials INI file.")

    def more_info(self):  # pylint: disable=missing-docstring,no-self-use
        return (
            "This plugin configures a DNS TXT record to respond to a dns-01 challenge using "
            "the ISPConfig Remote REST API."
        )

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            "credentials",
            "ISPConfig credentials INI file",
            {
                "endpoint": "URL of the ISPConfig Remote API.",
                "username": "Username for ISPConfig Remote API.",
                "password": "Password for ISPConfig Remote API.",
            },
        )

    def _perform(self, domain, validation_name, validation):
        self._get_ispconfig_client().add_txt_record(
            domain, validation_name, validation, self.ttl
        )

    def _cleanup(self, domain, validation_name, validation):
        self._get_ispconfig_client().del_txt_record(
            domain, validation_name, validation, self.ttl
        )

    def _get_ispconfig_client(self):
        return _ISPConfigClient(
            self.credentials.conf("endpoint"),
            self.credentials.conf("username"),
            self.credentials.conf("password"),
        )


class _ISPConfigClient(object):
    """
    Encapsulates all communication with the ISPConfig Remote REST API.
    """
    def __init__(self, endpoint, username, password):
        logger.debug("creating ispconfigclient")
        self.endpoint = endpoint.rstrip("?")
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.session_id = None

    def _login(self):
        if self.session_id is not None:
            return
        logger.debug("logging in")
        logindata = {"username": self.username, "password": self.password}
        self.session_id = self._api_request("login", logindata)
        logger.debug("session id is %s", self.session_id)

    def _api_request(self, action, data):
        if self.session_id is not None:
            data["session_id"] = self.session_id
        url = self._get_url(action)
        resp = self.session.post(url, json=data, timeout=30)
        logger.debug("API request to URL: %s", url)

        if resp.status_code != 200:
            raise errors.PluginError("HTTP Error during API call %s" % resp.status_code)

        try:
            result = resp.json()
        except json.decoder.JSONDecodeError:
            raise errors.PluginError("API response with non JSON: %s" % resp.text)

        if result.get("code") == "ok":
            return result.get("response")
        if result.get("code") == "remote_fault":
            raise errors.PluginError("API response with an error: %s" % result.get("message"))
        raise errors.PluginError("API response unknown %s" % resp.text)

    def _get_url(self, action):
        return "%s?%s" % (self.endpoint, action)

    def _get_server_id(self, zone_id):
        zone = self._api_request("dns_zone_get", {"primary_id": zone_id})
        if isinstance(zone, dict) and "server_id" in zone:
            return zone["server_id"]
        raise errors.PluginError("Could not determine server_id for zone %s" % zone_id)

    def _find_managed_zone_id(self, domain):
        candidates = sorted(dns_common.base_domain_name_guesses(domain), key=len, reverse=True)
        for zone_name in candidates:
            try:
                logger.debug("looking for zone: %s", zone_name)
                zone_id = self._api_request("dns_zone_get_id", {"origin": zone_name})
                if isinstance(zone_id, dict) and "id" in zone_id:
                    zone_id = zone_id["id"]
                return zone_id, zone_name
            except errors.PluginError:
                continue
        return None, None

    def _relative_record_name(self, record_name, zone_name):
        suffix = "." + zone_name
        if record_name.endswith(suffix):
            return record_name[:-len(suffix)]
        return record_name

    def _prepare_rr_data(self, zone_id, record_name, record_content, record_ttl):
        server_id = self._get_server_id(zone_id)
        return {
            "client_id": None,
            "rr_type": "TXT",
            "update_serial": True,
            "params": {
                "server_id": server_id,
                "name": record_name,
                "active": "Y",
                "type": "TXT",
                "data": record_content,
                "zone": zone_id,
                "ttl": record_ttl,
                "serial": str(int(time.time())),
                "stamp": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
            },
        }

    def _insert_txt_record(self, zone_id, record_name, record_content, record_ttl):
        data = self._prepare_rr_data(zone_id, record_name, record_content, record_ttl)
        logger.debug("insert with data: %s", data)
        self._api_request("dns_txt_add", data)

    def _update_txt_record(self, zone_id, primary_id, record_name, record_content, record_ttl):
        data = self._prepare_rr_data(zone_id, record_name, record_content, record_ttl)
        data["primary_id"] = primary_id
        logger.debug("update with data: %s", data)
        self._api_request("dns_txt_update", data)

    def _delete_txt_record(self, primary_id):
        data = {"primary_id": primary_id}
        logger.debug("delete with data: %s", data)
        self._api_request("dns_txt_delete", data)

    def get_existing_txts(self, zone_id, record_name):
        self._login()
        zone_data = self._api_request("dns_rr_get_all_by_zone", {"zone_id": zone_id})
        if not isinstance(zone_data, list):
            return []
        return [
            entry for entry in zone_data
            if entry.get("name") == record_name and entry.get("type") == "TXT"
        ]

    def add_txt_record(self, domain, record_name, record_content, record_ttl):
        self._login()
        zone_id, zone_name = self._find_managed_zone_id(domain)
        if zone_id is None:
            raise errors.PluginError("Domain not known")

        logger.debug("domain found: %s with id: %s", zone_name, zone_id)
        record_name = self._relative_record_name(record_name, zone_name)
        logger.debug("using record_name: %s", record_name)

        records = self.get_existing_txts(zone_id, record_name)
        for record in records:
            if record.get("data") == record_content:
                logger.info("already there, id %s", record.get("id"))
                return

        logger.info("insert new txt record")
        self._insert_txt_record(zone_id, record_name, record_content, record_ttl)

    def del_txt_record(self, domain, record_name, record_content, record_ttl):
        self._login()
        zone_id, zone_name = self._find_managed_zone_id(domain)
        if zone_id is None:
            raise errors.PluginError("Domain not known")

        logger.debug("domain found: %s with id: %s", zone_name, zone_id)
        record_name = self._relative_record_name(record_name, zone_name)
        logger.debug("using record_name: %s", record_name)

        records = self.get_existing_txts(zone_id, record_name)
        for record in records:
            if record.get("data") == record_content:
                logger.debug("delete TXT record: %s", record.get("id"))
                self._delete_txt_record(record.get("id"))
                return
