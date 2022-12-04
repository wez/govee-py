import math
from typing import Tuple


def clamp(value: int, lower: int, upper: int) -> int:
    """Clamp a value to a specified range"""
    return max(min(value, upper), lower)


def k_to_rgb(
    kelvin: int,
) -> Tuple[int, int, int]:
    """Compute an rgb value corresponding to a color temperature in kelvin.
    Uses an approximation based on:
    http://www.tannerhelland.com/4435/convert-temperature-rgb-algorithm-code/
    """
    kelvin = clamp(kelvin, 1000, 40000)

    temperature = kelvin / 100.0

    if temperature <= 66:
        red = 255.0
    else:
        red = 329.698727446 * math.pow(temperature - 60, -0.1332047592)

    if temperature <= 66:
        green = 99.4708025861 * math.log(temperature) - 161.1195681661
    else:
        green = 288.1221695283 * math.pow(temperature - 60, -0.0755148492)

    if temperature >= 66:
        blue = 255.0
    elif temperature <= 19:
        blue = 0.0
    else:
        blue = 138.5177312231 * math.log(temperature - 10) - 305.0447927307

    return clamp(int(red), 0, 255), clamp(int(green), 0, 255), clamp(int(blue), 0, 255)
