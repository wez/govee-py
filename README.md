# Control Govee LED Lights from Python

This library provides control over Govee-manufactured lights.
@wez built this for use with Home Assistant.

It has an emphasis on making use of their [LAN
API](https://app-h5.govee.com/user-manual/wlan-guide) but also makes use of
their [HTTP
API](https://govee-public.s3.amazonaws.com/developer-docs/GoveeDeveloperAPIReference.pdf)
in order to retrieve the user-assigned names of the devices, and to control the
devices that don't yet support the LAN API.

## Getting Started

```python

from govee_led_wez import GoveeController, GoveeDevice

controller = GoveeController()

def device_changed(device: GoveeDevice):
    print(f"{device.device_id} state -> {device.state}")

controller.set_device_change_callback(device_changed)
if YOUR_API_KEY:
    controller.set_http_api_key(YOUR_API_KEY)
    controller.start_http_poller()
controller.start_lan_poller()

# Devices will now be discovered asynchronously
```

## Notes

*Devices are discovered asynchronously*. While the full set of devices
associated with your account can be returned via the HTTP API, the
initial request for them is made asynchronously by the background
http poller task.  If you need the list immediately, you can call
`controller.query_http_devices()` to obtain that list.


*The HTTP API has some tight rate limits*. This library prefers to avoid
read-after-write operations to verify the state in order to reserve the calls
for issuing commands to your devices.  This means that, for devices that don't
support the LAN API, the assumed state may be a bit wonky until the device
is controlled. You can call `controller.update_device_state()` to
explicitly retrieve the state.

# Contributing

A `Makefile` provides shortcuts for doing stuff:

* `make setup` - do one-time setup for developing
* `make check` - performs type checking and linting
* `make test` - runs tests
* `make fmt` - runs code formatting, potentially appeasing `make check`
* `make build` - builds distributable bits

GitHub Actions will run the `check`, `test` and `build` actions on PRs.
