# syntax=harbor.openfuyao.com/infra/dockerfile:1.9.0

# Copyright (c) 2024 Huawei Technologies Co., Ltd.
# openFuyao is licensed under Mulan PSL v2.
# You can use this software according to the terms and conditions of
# You may obtain a copy of Mulan PSL v2 at:
#          http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRIN
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

ARG GO_VERSION=1.21.8
ARG GO_IMAGE=harbor.openfuyao.com/openfuyao/golang:${GO_VERSION}-onbuild
ARG PKG=./cmd/oauth-server

# stage 1: build
FROM ${GO_IMAGE} AS build

# stage 2: final
FROM harbor.openfuyao.com/openfuyao/base-layout AS final

WORKDIR /

COPY --link --from=build --chmod=755 /go/bin/app entrypoint
COPY --link --from=build --chmod=644 /go/src/app/assets/templates/loginBackground.png loginBackground.png

ENTRYPOINT [ "./entrypoint" ]
