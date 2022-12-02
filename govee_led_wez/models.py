from dataclasses import dataclass
from enum import Enum
from typing import Dict


class BleColorMode(Enum):
    """The packet format for updating colors"""

    MODE_2 = 1
    MODE_D = 2
    MODE_1501 = 3


@dataclass
class ModelInfo:
    """Describes what we know about a given device model"""

    ble_color_mode: BleColorMode = BleColorMode.MODE_2
    ble_brightness_max: int = 255

    @staticmethod
    def resolve(model: str):
        """Lookup model and returns its info. If no info is found,
        assume a reasonable default, which may not be accurate"""
        if info := INFO_BY_MODEL.get(model, None):
            return info
        return ModelInfo()


INFO_BY_MODEL: Dict[str, ModelInfo] = {
    "H613B": ModelInfo(BleColorMode.MODE_D, ble_brightness_max=100),
    "H613D": ModelInfo(BleColorMode.MODE_D, ble_brightness_max=100),
    "H617E": ModelInfo(BleColorMode.MODE_D, ble_brightness_max=100),
    "H6102": ModelInfo(BleColorMode.MODE_1501, ble_brightness_max=100),
    "H6072": ModelInfo(BleColorMode.MODE_1501, ble_brightness_max=100),
    "H6058": ModelInfo(BleColorMode.MODE_D, ble_brightness_max=100),
}
