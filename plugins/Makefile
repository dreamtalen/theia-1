version=$(shell cat policy_recommendation/version.txt | sed 's/\./_/g')

.PHONY: all
all: policy_recommendation

policy_recommendation:
	@zip $@_$(version).zip -r policy_recommendation -i '*.py'

.PHONY: clean
clean:
	rm -f *.zip

.PHONY: check
check:
	PYTHONPATH="${PYTHONPATH}:$(CURDIR)" python3 -m unittest discover policy_recommendation "*_test.py"
