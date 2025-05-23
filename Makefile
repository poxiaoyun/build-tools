BIN_DIR?=bin

all: build

BUILD_TARGET?=./cmd/...

define build-binary
	@echo "Building ${1}-${2}";
	@mkdir -p ${BIN_DIR}/${1}-${2};
	GOOS=${1} GOARCH=$(2) CGO_ENABLED=0 go build -gcflags=all="-N -l" -ldflags="${LDFLAGS}" -o ${BIN_DIR}/${1}-${2} $(BUILD_TARGET)
endef
build:
	$(call build-binary,linux,amd64)
	$(call build-binary,linux,arm64)
	$(call build-binary,darwin,amd64)
	$(call build-binary,darwin,arm64)
	$(call build-binary,windows,amd64)
	$(call build-binary,windows,arm64)
