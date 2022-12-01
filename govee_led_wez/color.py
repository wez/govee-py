from dataclasses import dataclass
from typing import Dict, Tuple

from .kelvin_rgb import k_to_rgb


def clamp(value, lower, upper):
    """Clamp a value to a specified range"""
    return max(min(value, upper), lower)


@dataclass
class GoveeColor:
    """Represents an sRGB color"""

    red: int = 0
    green: int = 0
    blue: int = 0

    def as_tuple(self) -> Tuple[int, int, int]:
        """Returns (r, g, b)"""
        return (self.red, self.green, self.blue)

    def as_json_object(self) -> Dict[str, int]:
        """Returns {"r":r, "g":b, "b":b}"""
        return {"r": self.red, "g": self.green, "b": self.blue}

    @staticmethod
    def from_kelvin(kelvin: int):
        """Computes the rgb equivalent to a color temperature specified
        in kelvin"""

        red, green, blue = k_to_rgb(kelvin)
        print(f"{kelvin} -> {red}, {green}, {blue}")

        return GoveeColor(
            red=red,
            green=green,
            blue=blue,
        )
