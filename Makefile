# SHELL ensures more consistent behavior between macOS and Linux.
SHELL=/bin/bash

test_reports := build

.PHONY: *


clean:
	rm -rf build .mypy_cache .coverage


# Install the script locally.
install:
	pip3 install -e .


# Install the script and the development dependencies.
dev-install:
	pip3 install -r dev-requirements.txt


uninstall:
	pip3 uninstall aws2wrap

# Run the unittests.w
test:
	rm -rf $(test_reports) .coverage
	mkdir -p $(test_reports)
	python3 -m green --run-coverage --junit-report=$(test_reports)/pytests.xml aws2wrap
	python3 -m coverage xml -o $(test_reports)/pycoverage.xml
	python3 -m coverage html -d $(test_reports)/html
	@echo "HTML code coverage report was generated in $(test_reports)/html"
	@echo "Open it with:"
	@echo "  open $(test_reports)/html/index.html"


# Run pylint to help check that our code is sane.
pylint:
	python3 -m pylint --errors-only setup.py aws2wrap


# Run mypy to check that our type annotation is correct.
mypy:
	python3 -m mypy aws2wrap


checks: pylint mypy test
