# Copyright 2020 Google LLC

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This Dockerfile assembles an image containing minimal components to
# launch Runtime Tests triggered by a Prow job.

FROM ubuntu:18.04
COPY provision.sh /tmp
ENV GOPATH=/go
ENV GOROOT=/usr/local/go
ENV PATH=$GOROOT/bin:$GOPATH/bin:/google-cloud-sdk/bin:/workspace:$PATH
RUN chmod +x /tmp/provision.sh
RUN /tmp/provision.sh
