import requests
import urllib3
from datetime import datetime, timedelta

"""
Unifi Controller API
"""


# disable insecure SSL warning, no unifi controller has a valid ssl cert anyway
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Client:

    """
    A client device on the unifi controller
    """

    def __init__(self, json):
        self.mac = json.get("mac")
        self.hostname = json.get("hostname")
        self.first_seen = self._to_date(json.get("first_seen"))
        self.last_seen = self._to_date(json.get("last_seen"))
        self.is_wired = json.get("is_wired")
        self.is_guest = json.get("is_guest")

    @staticmethod
    def _to_date(timestamp):
        if timestamp and type(timestamp) == int:
            return datetime.fromtimestamp(timestamp)
        return None

    @property
    def duration(self):

        """
        The duration from first_seen to last_seen
        """

        if self.first_seen is not None and self.last_seen is not None:
            return self.last_seen - self.first_seen
        return timedelta(0)


class Unifi:

    """
    Unifi API commands
    See https://ubntwiki.com/products/software/unifi-controller/api for more details

    You need to run login() first before you can run any commands
    An UnauthorizedError will be raised if you are not logged in

    If the site_name variable is not set, "default" will be used

    host        = The unifi controller's IP address or hostname
    username    = The username for the controller
    password    = The password for the controller
    site_name   = The site name in the controller to query
    port        = The port the controller web interface is listening on (usually 8443)
    """

    def __init__(self, host, username, password, site_name=None, port=8443):
        self.url = f"https://{host}:{port}"
        self.timeout = 5
        self._username = username
        self._password = password
        self._session = None

        # if the site name is not specified, it will default to "default"
        self.site_name = site_name or "default"

    @property
    def session(self):
        if not self._session:
            adapter = requests.adapters.HTTPAdapter(max_retries=3)
            self._session = requests.Session()
            self._session.mount("https://", adapter)
        return self._session

    def get(self, relative_url, **kwargs):
        res = self.session.get(self.url + relative_url, timeout=self.timeout, verify=False, **kwargs)

        if res.status_code == 200:
            return res
        elif res.status_code == 401:
            raise UnauthorizedError()
        else:
            raise UnhandledResponseCode(res.status_code)

    def post(self, relative_url, **kwargs):
        res = self.session.post(self.url + relative_url, timeout=self.timeout, verify=False, **kwargs)

        if res.status_code == 200:
            return res
        elif res.status_code == 401:
            raise UnauthorizedError()
        else:
            raise UnhandledResponseCode(res.status_code)

    def login(self):
        res = self.post("/api/login", json={
            "username": self._username,
            "password": self._password
        })
        self.session.cookies.update(res.cookies.get_dict())

    def whoami(self):
        r = self.session.get(f"{self.url}/api/self")

        if r.status_code == 200:

            data = r.json()
            name = data["data"][0]["name"]
            last_site = data["data"][0]["last_site_name"]

            print(f"Hello {name}, looks like you last used the site '{last_site}' and we are using the site '{self.site_name}' for this session.")

        elif r.status_code == 401:
            print("Oops, you are not authorized, did you log in?")

        else:
            print("Oops, there was a problem finding your info")

    def devices(self):
        r = self.get(f"/api/s/{self.site_name}/rest/user")
        device_list = r.json().get("data", [])
        return [Client(i) for i in device_list]

    def unauthorize(self, mac):

        """
        Unauthorize the client provided the client's MAC address
        """

        # TODO: verify this is unauthorizing a radius session?
        #  best to use this with radius vs disconnect() ?

        # stamgr	unauthorize-guest	Unauthorize a client device, mac = client mac (required)
        r = self.post(f"/api/s/{self.site_name}/cmd/stamgr", json={"cmd": "unauthorize-guest", "mac": mac})
        return r

    def disconnect(self, mac):

        """
        Disconnect the client from the wifi provided the client's MAC address
        """

        # stamgr	kick-sta	Disconnect: mac = client mac (required )
        r = self.post(f"/api/s/{self.site_name}/cmd/stamgr", json={"cmd": "kick-sta", "mac": mac})
        return r


class UnifiError(Exception):
    # raise when an error occurs in the API
    pass


class UnauthorizedError(UnifiError):
    # raise when a 401 error is returned
    def __init__(self):
        super(UnauthorizedError, self).__init__("Unauthorized, make sure you are logged in")


class UnifiLoginError(UnifiError):
    # raise when there was a problem logging in
    def __init__(self):
        super(UnifiLoginError, self).__init__("Couldn't log in to the Unifi controller")


class UnhandledResponseCode(UnifiError):
    # raise when a response code is returned but not handled
    def __init__(self, code):
        super(UnhandledResponseCode, self).__init__(f"Received code [{code}] from response and was unhandled")


if __name__ == "__main__":

    pass
