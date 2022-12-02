import logging
import time
from typing import Optional
from uuid import UUID

from bleak import AdvertisementData, BleakClient, BLEDevice
from bleak_retry_connector import establish_connection

from .color import GoveeColor
from .models import BleColorMode, ModelInfo

GOVEE_MFR = [34817, 34818]
GOVEE_SVC = UUID("00010203-0405-0607-0809-0a0b0c0d1910")
GOVEE_CHR = UUID("00010203-0405-0607-0809-0a0b0c0d2b11")

_LOGGER = logging.getLogger(__name__)


def is_govee_device(adv: AdvertisementData) -> bool:
    """Given advertising data from a BLE device, return True if
    the device appears to be a Govee LED device"""
    for mfr in GOVEE_MFR:
        if mfr in adv.manufacturer_data:
            return True
    return False


class BleDeviceEntry:
    """Holds information about a ble device, as needed by the controller"""

    device: BLEDevice
    client: Optional[BleakClient] = None
    last_use: Optional[float] = None

    def __init__(self, device: BLEDevice):
        self.device = device

    async def connect(self) -> BleakClient:
        """Connect to the device. If the device is already connected,
        return that existing client object"""
        if self.client:
            self.last_use = time.monotonic()
            return self.client

        _LOGGER.debug("Attempt to connect to %s", self.device)

        def disconnected(client: BleakClient):
            if self.client == client:
                self.client = None
                self.last_use = None

        client = await establish_connection(
            BleakClient,
            self.device,
            name=self.device.address,
            disconnected_callback=disconnected,
        )
        self.client = client
        self.last_use = time.monotonic()
        return client

    async def write_gatt_char(self, data: bytes):
        """Write a packet to the control characteristic.
        Will attempt to obtain a client implicitly"""
        client = await self.connect()
        _LOGGER.debug("calling write_gatt_char %s %s", self.device, data)
        await client.write_gatt_char(GOVEE_CHR, data)

    async def disconnect(self):
        """Disconnect the ble client, if connected"""
        if self.client:
            _LOGGER.debug("Disconnecting client from %s", self.device)
            await self.client.disconnect()
            self.client = None
            self.last_use = None


class GoveeBlePacket:
    """A BLE packet, per the information determined in
    <https://github.com/egold555/Govee-Reverse-Engineering/blob/master/Products/H6127.md>
    """

    def __init__(self):
        self.data = [0]

    def finish(self) -> bytes:
        """Compute the checksum and return the assembled packet as bytes"""
        checksum = 0
        for byte in self.data:
            checksum ^= byte
        while len(self.data) < 20:
            self.data.append(0)
        self.data[19] = checksum
        return bytes(self.data)

    @staticmethod
    def power(is_on: bool) -> bytes:
        """Compute a power on/off packet"""
        pkt = GoveeBlePacket()
        pkt.data = [0x33, 0x01, 0x01 if is_on else 0x00]
        return pkt.finish()

    @staticmethod
    def brightness(level_pct: int, model_info: ModelInfo) -> bytes:
        """Compute a brightness packet"""
        pkt = GoveeBlePacket()
        pkt.data = [
            0x33,
            0x04,
            int(round(level_pct * model_info.ble_brightness_max / 100)),
        ]
        return pkt.finish()

    @staticmethod
    def rgb_color(color: GoveeColor, model_info: ModelInfo) -> bytes:
        """Compute an rgb color packet"""
        pkt = GoveeBlePacket()
        if model_info.ble_color_mode == BleColorMode.MODE_D:
            pkt.data = [0x33, 0x05, 0x0D, color.red, color.green, color.blue]
        elif model_info.ble_color_mode == BleColorMode.MODE_1501:
            pkt.data = [
                0x33,
                0x05,
                0x15,
                0x01,
                color.red,
                color.green,
                color.blue,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0xFF,
                0x74,
            ]
        elif model_info.ble_color_mode == BleColorMode.MODE_2:
            pkt.data = [0x33, 0x05, 0x02, color.red, color.green, color.blue]
        else:
            raise RuntimeError(f"unhandled ble_color_mode {model_info}")
        return pkt.finish()

    @staticmethod
    def color_temperature(temperature: int, model_info: ModelInfo) -> bytes:
        """Compute an rgb color packet"""

        color = GoveeColor.from_kelvin(temperature)

        pkt = GoveeBlePacket()
        if model_info.ble_color_mode == BleColorMode.MODE_D:
            pkt.data = [
                0x33,
                0x05,
                0x0D,
                0xFF,
                0xFF,
                0xFF,
                0x01,
                color.red,
                color.green,
                color.blue,
            ]
        elif model_info.ble_color_mode == BleColorMode.MODE_1501:
            pkt.data = [
                0x33,
                0x05,
                0x15,
                0x01,
                0xFF,
                0xFF,
                0xFF,
                (temperature >> 8) & 0xFF,
                temperature & 0xFF,
                0xFF,
                0x89,
                0x12,
                0xFF,
                0x74,
            ]
        elif model_info.ble_color_mode == BleColorMode.MODE_2:
            pkt.data = [
                0x33,
                0x05,
                0x02,
                0xFF,
                0xFF,
                0xFF,
                0x01,
                color.red,
                color.green,
                color.blue,
            ]
        else:
            raise RuntimeError(f"unhandled ble_color_mode {model_info}")
        return pkt.finish()
