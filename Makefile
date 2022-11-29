build:
	python3 -m build

check:
	mypy govee_led_wez tests
	pylint govee_led_wez tests

fmt:
	black govee_led_wez/*.py tests/*.py
	isort govee_led_wez tests

test:
	pytest

setup:
	pip install flit
	flit install --deps=develop
