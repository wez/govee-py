# pylint: disable=redefined-outer-name
# pylint: disable=missing-class-docstring
# pylint: disable=missing-function-docstring

from govee_led_wez.kelvin_rgb import k_to_rgb


def test_kelvin():
    assert k_to_rgb(2000) == (255, 136, 13)
    assert k_to_rgb(7100) == (239, 240, 255)
