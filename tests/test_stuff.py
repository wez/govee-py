# pylint: disable=redefined-outer-name
# pylint: disable=missing-class-docstring
# pylint: disable=missing-function-docstring

import asyncio
import json
import queue

import pytest

from govee_led_wez import (
    GoveeColor,
    GoveeController,
    GoveeDeviceState,
    GoveeHttpDeviceDefinition,
)

http_responses: queue.Queue = queue.Queue()


# pylint: disable=unused-argument
def mocked_http_response(self, *args, **kwargs):
    response = http_responses.get()
    assert response is not None
    return response


class MockHttpResponse:
    def __init__(
        self,
        *,
        status=200,
        json=None,
        text=None,
        headers=None,
        check_kwargs=lambda kwargs: True,
    ):
        self._status = status
        self._json = json
        self._text = text
        self._check_kwargs = check_kwargs
        self._headers = headers

    def __repr__(self):
        return str(self.__dict__)

    @property
    def status(self):
        return self._status

    @property
    def headers(self):
        return self._headers

    async def json(self):
        return self._json

    async def text(self):
        if self._text is not None:
            return self._text
        if self._json:
            return json.dumps(self._json)
        raise RuntimeError("text property was not set")

    async def __aenter__(self):
        return self

    async def __aexit__(self, *error_info):
        return self

    def check_kwargs(self, kwargs):
        is_ok = self._check_kwargs(kwargs)
        if not is_ok:
            raise Exception(
                f"kwargs {kwargs} did not pass kwargs checker {self._check_kwargs}"
            )


@pytest.fixture
def mock_http_client(monkeypatch):
    monkeypatch.setattr("aiohttp.ClientSession.get", mocked_http_response)
    monkeypatch.setattr("aiohttp.ClientSession.put", mocked_http_response)


lan_disco: asyncio.Queue = asyncio.Queue()

# pylint: disable=protected-access
async def mocked_lan_poller(controller, interface, interval):
    while True:
        message, addr = await lan_disco.get()
        controller._lan_poller_process_broadcast(message, addr)


def mocked_send_lan_command(self, lan_definition, cmd):
    if cmd["msg"]["cmd"] == "devStatus":
        lan_disco.put_nowait(
            (
                {
                    "msg": {
                        "cmd": "devStatus",
                        "data": {
                            "onOff": 1,
                            "brightness": 100,
                            "color": {"r": 255, "g": 0, "b": 0},
                        },
                    }
                },
                (lan_definition.ip_addr, 4003),
            )
        )


@pytest.fixture
def mock_lan_bits(monkeypatch):
    monkeypatch.setattr("govee_led_wez.GoveeController._lan_poller", mocked_lan_poller)
    monkeypatch.setattr(
        "govee_led_wez.GoveeController._send_lan_command", mocked_send_lan_command
    )


@pytest.mark.asyncio
async def test_device_lan(mock_lan_bits):
    assert lan_disco.empty()
    controller = GoveeController()
    changed = asyncio.Queue()
    controller.set_device_change_callback(changed.put_nowait)
    controller.start_lan_poller()

    lan_disco.put_nowait(
        (
            {
                "msg": {
                    "cmd": "scan",
                    "data": {
                        "ip": "10.0.0.1",
                        "device": "11:11:11:11:11:11:11:11",
                        "sku": "H6160",
                        "bleVersionHard": "3.01.01",
                        "bleVersionSoft": "1.03.01",
                        "wifiVersionHard": "1.00.10",
                        "wifiVersionSoft": "1.02.03",
                    },
                }
            },
            ("10.0.0.1", 4003),
        )
    )

    device = await changed.get()
    assert device.device_id == "11:11:11:11:11:11:11:11"

    await controller.update_device_state(device)
    assert device.state == GoveeDeviceState(
        turned_on=True,
        brightness_pct=100,
        color=GoveeColor(red=255, green=0, blue=0),
        color_temperature=None,
    )

    controller.stop()


@pytest.mark.asyncio
async def test_device_list_ok(mock_http_client):
    assert http_responses.empty()
    http_responses.put(
        MockHttpResponse(
            status=200,
            json={
                "data": {
                    "devices": [
                        {
                            "device": "11:11:11:11:11:11:11:11",
                            "model": "H6160",
                            "deviceName": "A Light",
                            "controllable": True,
                            "retrievable": True,
                            "supportCmds": ["turn", "brightness", "color", "colorTem"],
                            "properties": {
                                "colorTem": {"range": {"min": 2000, "max": 9000}}
                            },
                        }
                    ]
                }
            },
        )
    )
    controller = GoveeController()
    controller.set_http_api_key("dummy")
    http_devices = await controller.query_http_devices()
    assert http_responses.empty()
    assert http_devices == [
        GoveeHttpDeviceDefinition(
            device_id="11:11:11:11:11:11:11:11",
            model="H6160",
            device_name="A Light",
            controllable=True,
            retrievable=True,
            supported_commands=["turn", "brightness", "color", "colorTem"],
            properties={"colorTem": {"range": {"min": 2000, "max": 9000}}},
        )
    ]

    device = controller.get_device_by_id(http_devices[0].device_id)
    assert device.state is None

    http_responses.put(
        MockHttpResponse(
            status=200,
            json={
                "data": {
                    "device": "11:11:11:11:11:11:11:11",
                    "model": "H6160",
                    "properties": [
                        {"online": "true"},
                        {"powerState": "on"},
                        {"brightness": 82},
                        {"color": {"r": 255, "g": 100, "b": 80}},
                    ],
                },
                "message": "Success",
                "code": 200,
            },
        )
    )

    await controller.update_device_state(device)
    assert device.state == GoveeDeviceState(
        turned_on=True,
        brightness_pct=82,
        color=GoveeColor(red=255, green=100, blue=80),
        color_temperature=None,
    )

    http_responses.put(
        MockHttpResponse(
            status=200,
            json={
                "data": {},
                "message": "Success",
                "code": 200,
            },
        )
    )
    await controller.set_power_state(device, False)
    assert device.state == GoveeDeviceState(
        turned_on=False,
        brightness_pct=82,
        color=GoveeColor(red=255, green=100, blue=80),
        color_temperature=None,
    )

    http_responses.put(
        MockHttpResponse(
            status=400,
            json={
                "data": {},
                "message": "Failure",
                "code": 400,
            },
        )
    )
    with pytest.raises(RuntimeError, match="failed to control device: Failure"):
        await controller.set_power_state(device, True)

    assert device.state == GoveeDeviceState(
        turned_on=False,
        brightness_pct=82,
        color=GoveeColor(red=255, green=100, blue=80),
        color_temperature=None,
    )


@pytest.mark.asyncio
async def test_device_list_fail(mock_http_client):
    assert http_responses.empty()
    http_responses.put(MockHttpResponse(status=400, text="failed for some reason"))

    with pytest.raises(RuntimeError, match="failed for some reason"):
        controller = GoveeController()
        controller.set_http_api_key("dummy")
        await controller.query_http_devices()
