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

#include <cstdint>
#include <limits>

namespace olp {
namespace network2 {

/**
 * @brief Represents a unique request id.
 * Values of this type mark a unique request all the way until completion.
 * This value is returned by Network::Send, used by
 * Network::Cancel and NetworkResponse so that the user can track a request all
 * the way.
 */
using RequestId = std::uint64_t;

/**
 * @brief List of special values for NetworkRequestId.
 */
enum class RequestIdConstants : RequestId {
  /// Value that indicates invalid request id.
  RequestIdInvalid = std::numeric_limits<RequestId>::min(),
  /// Minimal value of valid request id.
  RequestIdMin = std::numeric_limits<RequestId>::min() + 1,
  /// Maximal value of valid request id.
  RequestIdMax = std::numeric_limits<RequestId>::max(),
};

/**
 * @brief Common Network error codes.
 */
enum class ErrorCode {
  NO_ERROR = 0,
  IO_ERROR = -1,
  AUTHORIZATION_ERROR = -2,
  INVALID_URL_ERROR = -3,
  OFFLINE_ERROR = -4,
  CANCELLED_ERROR = -5,
  AUTHENTICATION_ERROR = -6,
  TIMEOUT_ERROR = -7,
  UNKNOWN_ERROR = -8,
};

/**
 * @brief Helper class representing the outcome of making a network request.
 * It will contain either a valid RequestId or the error code in case request
 * trigger failed.  The caller must check whether the outcome of the request was
 * a success before attempting to access the result or the error.
 */
class SendOutcome final {
 public:
  SendOutcome(RequestId request_id) : request_id_(request_id) {}
  SendOutcome(ErrorCode error_code) : error_code_(error_code) {}

  /**
   * @brief Check if network request push was successfull.
   * @return \c true in case there is no error and a valid RequestId, \c false
   * otherwise.
   */
  bool IsSuccessfull() const {
    return error_code_ == ErrorCode::NO_ERROR &&
           request_id_ !=
               static_cast<RequestId>(RequestIdConstants::RequestIdInvalid);
  }

  /**
   * @brief Get request id.
   * @return A valid RequestId in case request was successfull, \c
   * RequestIdConstants::RequestIdInvalid otherwise.
   */
  const RequestId& GetRequestId() const { return request_id_; }

  /**
   * @brief Get error code.
   * @return \c ErrorCode::NO_ERROR in case request was successfull, any other
   * ErrorCode otherwise.
   */
  const ErrorCode& GetErrorCode() const { return error_code_; }

 private:
  /// Request ID.
  RequestId request_id_{
      static_cast<RequestId>(RequestIdConstants::RequestIdInvalid)};
  /// Error code.
  ErrorCode error_code_{ErrorCode::NO_ERROR};
};

}  // namespace network2
}  // namespace olp
