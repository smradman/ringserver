# Build environment can be configured with the following
# environment variables:
#   CC : Specify the C compiler to use
#   CFLAGS : Specify compiler options to use

# Default to -O2 optimization level
export CFLAGS ?= -O2

SUBDIRS = pcre2 mxml libmseed mbedtls miniz
BUILDDIRS = $(SUBDIRS) src

# Disallow combining 'clean' with build goals: each directory is
# visited only once per invocation, so 'make clean all' would clean
# but never build.
ifneq ($(filter clean,$(MAKECMDGOALS)),)
  ifneq ($(filter-out clean,$(MAKECMDGOALS)),)
    $(error 'clean' must be run alone, e.g. 'make clean && make')
  endif
endif

.PHONY: all clean install test $(BUILDDIRS)

all:   TARGET = all
clean: TARGET = clean
all clean: $(BUILDDIRS)

$(BUILDDIRS):
	$(MAKE) -C $@ $(TARGET)

# The main program links against the vendored libs: build it last.
src: $(SUBDIRS)

# Run test suite against the built binary
test: all
	python3 -m unittest discover -s tests -v

install:
	@echo
	@echo "No install method"
	@echo "Copy the binary and documentation to desired location"
	@echo
