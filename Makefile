REPO_PREFIX := yunion.io/x/yke

GIT_COMMIT := $(shell git rev-parse --short HEAD)
GIT_VERSION := $(shell git describe --tags --abbrev=14 $(GIT_COMMIT)^{commit})
GIT_TREE_STATE := $(shell s=`git status --porcelain 2>/dev/null`; if [ -z "$$s"  ]; then echo "clean"; else echo "dirty"; fi)
BUILD_DATE := $(shell date -u +'%Y-%m-%dT%H:%M:%SZ')

LDFLAGS := "-w \
	-X $(REPO_PREFIX)/cmd.gitVersion=$(GIT_VERSION) \
	-X $(REPO_PREFIX)/cmd.gitCommit=$(GIT_COMMIT) \
	-X $(REPO_PREFIX)/cmd.buildDate=$(BUILD_DATE) \
	-X $(REPO_PREFIX)/cmd.gitTreeState=$(GIT_TREE_STATE)"

all: bin

bin: clean
	go build -ldflags $(LDFLAGS) -o bin/yke ./main.go

clean:
	rm -rf bin

rpm: bin
	./tools/rpm-maker
