/*
 * Copyright (C) 2019 HERE Europe B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * License-Filename: LICENSE
 */

#pragma once

#include <mutex>

#include "olp/core/network2/Network.h"

#ifdef __OBJC__
@class OLPHttpClient;
#else
typedef void OLPHttpClient;
#endif

namespace olp {
namespace network2 {

/**
 * @brief The implementation of Network2 interface on iOS using NSURLSession
 */
class OLPNetworkIOS : public olp::network2::Network {
 public:
  explicit OLPNetworkIOS(size_t max_requests_count);
  ~OLPNetworkIOS();

  olp::network2::NetworkStatus Send(
      olp::network2::NetworkRequest request,
      std::shared_ptr<std::ostream> payload,
      olp::network2::Network::Callback callback,
      olp::network2::Network::HeaderCallback header_callback = nullptr,
      olp::network2::Network::DataCallback data_callback = nullptr) override;

  void Cancel(olp::network2::RequestId identifier) override;

 private:
  void Cleanup();

  olp::network2::RequestId GenerateNextRequestId();

 private:
  const size_t max_requests_count_;
  OLPHttpClient* http_client_{nullptr};
  std::mutex mutex_;
  RequestId request_id_counter_{
      static_cast<RequestId>(RequestIdConstants::RequestIdMin)};
};
}  // namespace network2
}  // namespace olp
