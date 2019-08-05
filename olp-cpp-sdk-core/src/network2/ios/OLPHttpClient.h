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

#import <Foundation/Foundation.h>

#include "olp/core/network2/NetworkTypes.h"

@class OLPHttpTask;

namespace olp {
namespace network2 {
class NetworkProxySettings;
}  // network2
}  // olp

/**
 * \brief Utility client to create and manage runnable tasks via NSURLSession.
 */
@interface OLPHttpClient : NSObject

/// Creates a task with specific identifier with corresponding settings
- (OLPHttpTask *)createTaskWithProxy:
                     (const olp::network2::NetworkProxySettings &)proxySettings
                               andId:(olp::network2::RequestId)identifier;

/// Gets task by corresponding request id
- (OLPHttpTask *)taskWithId:(olp::network2::RequestId)identifier;

/// Removes the task with corresponding request id
- (void)removeTaskWithId:(olp::network2::RequestId)identifier;

/// Cancel the task with corresponding request id
- (void)cancelTaskWithId:(olp::network2::RequestId)identifier;

/// Finish all tasks in progress and invalidate all URL sessions
- (void)cleanup;

@end
