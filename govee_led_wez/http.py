from dataclasses import dataclass
import logging
import ssl
from typing import Any, Dict, List

import aiohttp
import certifi

_LOGGER = logging.getLogger(__name__)


@dataclass
class GoveeHttpDeviceDefinition:
    """Device information, available via HTTP API"""

    device_id: str
    model: str
    device_name: str
    controllable: bool
    retrievable: bool
    supported_commands: List[str]
    properties: Dict[str, Any]


async def _extract_failure_message(response) -> str:
    try:
        data = await response.json()
        if "message" in data:
            return data["message"]
    except Exception:  # pylint: disable=broad-except
        pass
    return await response.text()


async def http_get_devices(api_key: str) -> List[GoveeHttpDeviceDefinition]:
    """Requests the list of devices via the HTTP API"""
    ssl_context = ssl.create_default_context(cafile=certifi.where())
    conn = aiohttp.TCPConnector(ssl=ssl_context)
    message = "Failed for an unknown reason"
    async with aiohttp.ClientSession(connector=conn) as session:
        async with session.get(
            url="https://developer-api.govee.com/v1/devices",
            headers={"Govee-API-Key": api_key},
        ) as response:
            if response.status == 200:
                data = await response.json()
                if (
                    ("data" in data)
                    and ("devices" in data["data"])
                    and isinstance(data["data"]["devices"], list)
                ):
                    return [
                        GoveeHttpDeviceDefinition(
                            device_id=d["device"],
                            model=d["model"],
                            device_name=d["deviceName"],
                            controllable=d["controllable"],
                            retrievable=d["retrievable"],
                            supported_commands=d["supportCmds"],
                            properties=d["properties"],
                        )
                        for d in data["data"]["devices"]
                    ]

            message = await _extract_failure_message(response)
    raise RuntimeError(f"failed to get devices: {message}")


async def http_get_state(api_key: str, device_id: str, model: str) -> List[Any]:
    """Requests a list of properties representing the state of the specified device"""
    ssl_context = ssl.create_default_context(cafile=certifi.where())
    conn = aiohttp.TCPConnector(ssl=ssl_context)
    message = "Failed for an unknown reason"
    async with aiohttp.ClientSession(connector=conn) as session:
        async with session.get(
            url="https://developer-api.govee.com/v1/devices/state",
            headers={"Govee-API-Key": api_key},
            params={"model": model, "device": device_id},
        ) as response:
            if response.status == 200:
                data = await response.json()
                if "data" in data and "properties" in data["data"]:
                    return data["data"]["properties"]

            message = await _extract_failure_message(response)
    raise RuntimeError(f"failed to get device state: {message}")


async def http_device_control(api_key: str, params: Dict[str, Any]):
    """Sends a control request"""
    ssl_context = ssl.create_default_context(cafile=certifi.where())
    conn = aiohttp.TCPConnector(ssl=ssl_context)
    message = "Failed for an unknown reason"
    async with aiohttp.ClientSession(connector=conn) as session:
        async with session.put(
            url="https://developer-api.govee.com/v1/devices/control",
            headers={"Govee-API-Key": api_key},
            json=params,
        ) as response:
            _LOGGER.debug("http control request %s -> %s", params, response)
            if response.status == 200:
                resp = await response.json()
                return resp
            message = await _extract_failure_message(response)
    raise RuntimeError(f"failed to control device: {message}")
