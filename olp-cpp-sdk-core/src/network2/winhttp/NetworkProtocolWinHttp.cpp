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

#include "NetworkProtocolWinHttp.h"

#include <cassert>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "olp/core/logging/Log.h"
#include "olp/core/network2/Network.h"
#include "olp/core/network2/NetworkRequest.h"
#include "olp/core/network2/NetworkResponse.h"
#include "olp/core/network2/NetworkTypes.h"
#include "olp/core/porting/make_unique.h"

namespace {

constexpr int kNetworkUncompressionChunkSize = 1024 * 16;

LPCSTR
errorToString(DWORD err) {
  switch (err) {
    case ERROR_NOT_ENOUGH_MEMORY:
      return "Out of memory";
    case ERROR_WINHTTP_CANNOT_CONNECT:
      return "Cannot connect";
    case ERROR_WINHTTP_CHUNKED_ENCODING_HEADER_SIZE_OVERFLOW:
      return "Parsing overflow";
    case ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED:
      return "Authentication required";
    case ERROR_WINHTTP_CONNECTION_ERROR:
      return "Connection error";
    case ERROR_WINHTTP_HEADER_COUNT_EXCEEDED:
      return "Header count exceeded";
    case ERROR_WINHTTP_HEADER_SIZE_OVERFLOW:
      return "Header size overflow";
    case ERROR_WINHTTP_INCORRECT_HANDLE_STATE:
      return "Invalid handle state";
    case ERROR_WINHTTP_INCORRECT_HANDLE_TYPE:
      return "Invalid handle type";
    case ERROR_WINHTTP_INTERNAL_ERROR:
      return "Internal error";
    case ERROR_WINHTTP_INVALID_SERVER_RESPONSE:
      return "Invalid server response";
    case ERROR_WINHTTP_INVALID_URL:
      return "Invalid URL";
    case ERROR_WINHTTP_LOGIN_FAILURE:
      return "Login failed";
    case ERROR_WINHTTP_NAME_NOT_RESOLVED:
      return "Name not resolved";
    case ERROR_WINHTTP_OPERATION_CANCELLED:
      return "Cancelled";
    case ERROR_WINHTTP_REDIRECT_FAILED:
      return "Redirect failed";
    case ERROR_WINHTTP_RESEND_REQUEST:
      return "Resend request";
    case ERROR_WINHTTP_RESPONSE_DRAIN_OVERFLOW:
      return "Response overflow";
    case ERROR_WINHTTP_SECURE_FAILURE:
      return "Security error";
    case ERROR_WINHTTP_TIMEOUT:
      return "Timed out";
    case ERROR_WINHTTP_UNRECOGNIZED_SCHEME:
      return "Invalid scheme";
  }
  return "Unknown error";
}

olp::network2::ErrorCode errorToCode(DWORD err) {
  if (err == ERROR_SUCCESS)
    return olp::network2::ErrorCode::SUCCESS;
  else if ((err == ERROR_WINHTTP_INVALID_URL) ||
           (err == ERROR_WINHTTP_UNRECOGNIZED_SCHEME) ||
           (err == ERROR_WINHTTP_NAME_NOT_RESOLVED))
    return olp::network2::ErrorCode::INVALID_URL_ERROR;
  else if ((err == ERROR_WINHTTP_CLIENT_AUTH_CERT_NEEDED) ||
           (err == ERROR_WINHTTP_LOGIN_FAILURE) ||
           (err == ERROR_WINHTTP_SECURE_FAILURE))
    return olp::network2::ErrorCode::AUTHORIZATION_ERROR;
  else if (err == ERROR_WINHTTP_OPERATION_CANCELLED)
    return olp::network2::ErrorCode::CANCELLED_ERROR;
  else if (err == ERROR_WINHTTP_TIMEOUT)
    return olp::network2::ErrorCode::TIMEOUT_ERROR;
  return olp::network2::ErrorCode::IO_ERROR;
}

LPWSTR
queryHeadervalue(HINTERNET request, DWORD header) {
  DWORD len = 0, index = WINHTTP_NO_HEADER_INDEX;
  if (WinHttpQueryHeaders(request, header, WINHTTP_HEADER_NAME_BY_INDEX,
                          WINHTTP_NO_OUTPUT_BUFFER, &len, &index))
    return NULL;
  if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
    return NULL;
  }
  LPWSTR buffer = (LPWSTR)LocalAlloc(LPTR, len);
  if (!buffer) return NULL;
  index = WINHTTP_NO_HEADER_INDEX;
  if (!WinHttpQueryHeaders(request, header, WINHTTP_HEADER_NAME_BY_INDEX,
                           buffer, &len, &index)) {
    LocalFree(buffer);
    return NULL;
  }
  return buffer;
}

void UnixTimeToFileTime(std::uint64_t t, LPFILETIME pft) {
  // Note that LONGLONG is a 64-bit value
  LONGLONG ll;

  ll = Int32x32To64(t, 10000000) + 116444736000000000;
  pft->dwLowDateTime = (DWORD)ll;
  pft->dwHighDateTime = ll >> 32;
}

bool convertMultiByteToWideChar(const std::string& s_in, std::wstring& s_out) {
  s_out.clear();
  if (s_in.empty()) {
    return true;
  }

  // Detect required buffer size.
  const auto chars_required = MultiByteToWideChar(
      CP_ACP, MB_PRECOMPOSED, s_in.c_str(),
      -1,       // denotes null-terminated string
      nullptr,  // output buffer is null means request required buffer size
      0);

  if (chars_required == 0) {
    // error: could not convert input string
    return false;
  }

  s_out.resize(chars_required);
  // Perform actual conversion from multi-byte to wide char
  const auto conversion_result =
      MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, s_in.c_str(),
                          -1,  // denotes null-terminated string
                          &s_out.front(), s_out.size());

  if (conversion_result == 0) {
    // Should not happen as 1st call have succeeded.
    return false;
  }
  return true;
}
}  // namespace

namespace olp {
namespace network2 {

#define LOGTAG "WinHttp"

NetworkProtocolWinHttp::NetworkProtocolWinHttp()
    : http_session_(NULL),
      thread_(INVALID_HANDLE_VALUE),
      event_(INVALID_HANDLE_VALUE) {
  recent_request_id_.store(1);
  http_session_ = WinHttpOpen(L"NGMOS CLient", WINHTTP_ACCESS_TYPE_NO_PROXY,
                              WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS,
                              WINHTTP_FLAG_ASYNC);

  if (!http_session_) {
    EDGE_SDK_LOG_ERROR(LOGTAG, "WinHttpOpen failed " << GetLastError());
    return;
  }

  WinHttpSetStatusCallback(
      http_session_,
      (WINHTTP_STATUS_CALLBACK)&NetworkProtocolWinHttp::RequestCallback,
      WINHTTP_CALLBACK_FLAG_ALL_COMPLETIONS | WINHTTP_CALLBACK_FLAG_HANDLES, 0);

  event_ = CreateEvent(NULL, TRUE, FALSE, NULL);

  // Store the memory tracking state during initialization so that it can be
  // used by the thread.
  thread_ = CreateThread(NULL, 0, NetworkProtocolWinHttp::Run, this, 0, NULL);
  SetThreadPriority(thread_, THREAD_PRIORITY_ABOVE_NORMAL);
}

NetworkProtocolWinHttp::~NetworkProtocolWinHttp() {
  std::vector<std::shared_ptr<ResultData>> pendingResults;
  {
    std::unique_lock<std::recursive_mutex> lock(mutex_);
    std::vector<std::shared_ptr<RequestData>> requestsToCancel;
    for (auto& request : http_requests_) {
      requestsToCancel.push_back(request.second);
    }
    while (!requestsToCancel.empty()) {
      std::shared_ptr<RequestData> request = requestsToCancel.front();
      WinHttpCloseHandle(request->http_request);
      request->http_request = NULL;
      pendingResults.push_back(request->result_data);
      requestsToCancel.erase(requestsToCancel.begin());
    }
  }

  if (http_session_) {
    WinHttpCloseHandle(http_session_);
    http_session_ = NULL;
  }

  if (event_ != INVALID_HANDLE_VALUE) SetEvent(event_);
  if (thread_ != INVALID_HANDLE_VALUE) {
    if (GetCurrentThreadId() != GetThreadId(thread_)) {
      WaitForSingleObject(thread_, INFINITE);
    }
  }
  CloseHandle(event_);
  CloseHandle(thread_);
  thread_ = event_ = INVALID_HANDLE_VALUE;

  {
    std::unique_lock<std::recursive_mutex> lock(mutex_);
    http_connections_.clear();
    while (!results_.empty()) {
      pendingResults.push_back(results_.front());
      results_.pop();
    }
  }

  for (auto& result : pendingResults) {
    std::unique_lock<std::recursive_mutex> lock(mutex_);
    if (result->user_callback) {
      result->user_callback(
          NetworkResponse()
              .WithRequestId(result->request_id)
              .WithStatus(static_cast<int>(ErrorCode::OFFLINE_ERROR))
              .WithError("Offline"));
      result->user_callback = nullptr;
    }
  }
}

NetworkStatus NetworkProtocolWinHttp::Send(
    NetworkRequest request, std::shared_ptr<std::ostream> payload,
    Callback callback, HeaderCallback header_callback,
    DataCallback data_callback) {
  RequestId id = recent_request_id_.fetch_add(1);

  // if (!config->GetNetworkInterface().empty()) {
  //  return olp::network::NetworkProtocol::
  //      ErrorNetworkInterfaceOptionNotImplemented;
  //}

  // if (!config->GetCaCert().empty()) {
  //  return olp::network::NetworkProtocol::ErrorCaCertOptionNotImplemented;
  //}

  URL_COMPONENTS urlComponents;
  ZeroMemory(&urlComponents, sizeof(urlComponents));
  urlComponents.dwStructSize = sizeof(urlComponents);
  urlComponents.dwSchemeLength = (DWORD)-1;
  urlComponents.dwHostNameLength = (DWORD)-1;
  urlComponents.dwUrlPathLength = (DWORD)-1;
  urlComponents.dwExtraInfoLength = (DWORD)-1;

  std::wstring url(request.GetUrl().begin(), request.GetUrl().end());
  if (!WinHttpCrackUrl(url.c_str(), (DWORD)url.length(), 0, &urlComponents)) {
    EDGE_SDK_LOG_ERROR(LOGTAG, "WinHttpCrackUrl failed " << GetLastError());
    // return olp::network::NetworkProtocol::ErrorInvalidRequest;
    return NetworkStatus(ErrorCode::INVALID_URL_ERROR);
  }

  std::shared_ptr<RequestData> handle;
  {
    std::unique_lock<std::recursive_mutex> lock(mutex_);
    std::wstring server(url.data(), size_t(urlComponents.lpszUrlPath -
                                           urlComponents.lpszScheme));
    std::shared_ptr<ConnectionData> connection = http_connections_[server];
    if (!connection) {
      connection = std::make_shared<ConnectionData>(shared_from_this());
      INTERNET_PORT port = urlComponents.nPort;
      if (port == 0) {
        port = (urlComponents.nScheme == INTERNET_SCHEME_HTTPS)
                   ? INTERNET_DEFAULT_HTTPS_PORT
                   : INTERNET_DEFAULT_HTTP_PORT;
      }
      std::wstring hostName(urlComponents.lpszHostName,
                            urlComponents.dwHostNameLength);
      connection->http_connection =
          WinHttpConnect(http_session_, hostName.data(), port, 0);
      if (!connection->http_connection) {
        // return NetworkProtocol::ErrorNoConnection;
        return NetworkStatus(ErrorCode::OFFLINE_ERROR);
      }

      http_connections_[server] = connection;
    }

    connection->last_used = GetTickCount64();

    handle =
        std::make_shared<RequestData>(id, connection, callback, header_callback,
                                      data_callback, payload, request);
    http_requests_[id] = handle;
  }

  // handle->ignoreOffset = request.IgnoreOffset();
  // handle->getStatistics = request.GetStatistics();

  if ((urlComponents.nScheme != INTERNET_SCHEME_HTTP) &&
      (urlComponents.nScheme != INTERNET_SCHEME_HTTPS)) {
    EDGE_SDK_LOG_ERROR(LOGTAG,
                       "Invalid scheme on request " << request.GetUrl());

    std::unique_lock<std::recursive_mutex> lock(mutex_);

    http_requests_.erase(id);
    return NetworkStatus(ErrorCode::IO_ERROR);
  }

  DWORD flags = (urlComponents.nScheme == INTERNET_SCHEME_HTTPS)
                    ? WINHTTP_FLAG_SECURE
                    : 0;
  LPWSTR http_verb = L"GET";
  if (request.GetVerb() == NetworkRequest::HttpVerb::POST) {
    http_verb = L"POST";
  } else if (request.GetVerb() == NetworkRequest::HttpVerb::PUT) {
    http_verb = L"PUT";
  } else if (request.GetVerb() == NetworkRequest::HttpVerb::HEAD) {
    http_verb = L"HEAD";
  } else if (request.GetVerb() == NetworkRequest::HttpVerb::DEL) {
    http_verb = L"DELETE";
  } else if (request.GetVerb() == NetworkRequest::HttpVerb::PATCH) {
    http_verb = L"PATCH";
  }

  LPCSTR content = WINHTTP_NO_REQUEST_DATA;
  DWORD contentLength = 0;

  if (request.GetVerb() != NetworkRequest::HttpVerb::HEAD &&
      request.GetVerb() != NetworkRequest::HttpVerb::GET &&
      request.GetBody() != nullptr && !request.GetBody()->empty()) {
    content = (LPCSTR) & (request.GetBody()->front());
    contentLength = (DWORD)request.GetBody()->size();
  }

  /* Create a request */
  auto httpRequest =
      WinHttpOpenRequest(handle->connection_data->http_connection, http_verb,
                         urlComponents.lpszUrlPath, NULL, WINHTTP_NO_REFERER,
                         WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
  if (!httpRequest) {
    EDGE_SDK_LOG_ERROR(LOGTAG, "WinHttpOpenRequest failed " << GetLastError());

    std::unique_lock<std::recursive_mutex> lock(mutex_);

    http_requests_.erase(id);
    return NetworkStatus(ErrorCode::IO_ERROR);
  }

  const auto& network_settings = request.GetSettings();

  WinHttpSetTimeouts(httpRequest,
                     network_settings.GetConnectionTimeout() * 1000,
                     network_settings.GetConnectionTimeout() * 1000,
                     network_settings.GetTransferTimeout() * 1000,
                     network_settings.GetTransferTimeout() * 1000);

  // bool sysDontVerifyCertificate;
  // const auto sysConfigProxy = olp::network::Network::SystemConfig().locked(
  //    [&](const olp::network::NetworkSystemConfig& conf) {
  //      sysDontVerifyCertificate = conf.DontVerifyCertificate();
  //      return conf.GetProxy();
  //    });

  // if (sysDontVerifyCertificate) {
  //  flags = SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
  //          SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
  //          SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE |
  //          SECURITY_FLAG_IGNORE_UNKNOWN_CA;
  //  if (!WinHttpSetOption(httpRequest, WINHTTP_OPTION_SECURITY_FLAGS, &flags,
  //                        sizeof(flags))) {
  //    EDGE_SDK_LOG_ERROR(
  //        LOGTAG, "WinHttpSetOption(Security) failed " << GetLastError());
  //  }
  //}

  // const NetworkProxy* proxy = &sysConfigProxy;
  // if (config->Proxy().IsValid()) {
  //  proxy = &(config->Proxy());
  //}

  const auto& proxy = network_settings.GetProxySettings();

  if (proxy.GetType() != NetworkProxySettings::Type::NONE) {
    std::wostringstream proxy_string_stream;

    switch (proxy.GetType()) {
      case NetworkProxySettings::Type::NONE:
        proxy_string_stream << "http://";
        break;
      case NetworkProxySettings::Type::SOCKS4:
        proxy_string_stream << "socks4://";
        break;
      case NetworkProxySettings::Type::SOCKS5:
        proxy_string_stream << "socks5://";
        break;
      case NetworkProxySettings::Type::SOCKS4A:
        proxy_string_stream << "socks4a://";
        break;
      case NetworkProxySettings::Type::SOCKS5_HOSTNAME:
        proxy_string_stream << "socks5h://";
        break;
      default:
        proxy_string_stream << "http://";
    }

    proxy_string_stream << std::wstring(proxy.GetUsername().begin(),
                                        proxy.GetUsername().end());
    proxy_string_stream << ':';
    proxy_string_stream << proxy.GetPort();
    std::wstring proxy_string = proxy_string_stream.str();

    WINHTTP_PROXY_INFO proxy_info;
    proxy_info.dwAccessType = WINHTTP_ACCESS_TYPE_NAMED_PROXY;
    proxy_info.lpszProxy = const_cast<LPWSTR>(proxy_string.c_str());
    proxy_info.lpszProxyBypass = WINHTTP_NO_PROXY_BYPASS;

    DWORD error_code = ERROR_SUCCESS;
    if (!WinHttpSetOption(httpRequest, WINHTTP_OPTION_PROXY, &proxy_info,
                          sizeof(proxy_info))) {
      error_code = GetLastError();
      EDGE_SDK_LOG_ERROR(LOGTAG,
                         "WinHttpSetOption(Proxy) failed " << error_code);
    }
    if (!proxy.GetUsername().empty() && !proxy.GetUsername().empty()) {
      std::wstring proxy_username;
      const auto username_res =
          convertMultiByteToWideChar(proxy.GetUsername(), proxy_username);

      std::wstring proxy_password;
      const auto password_res =
          convertMultiByteToWideChar(proxy.GetPassword(), proxy_password);

      if (username_res && password_res) {
        LPCWSTR proxy_lpcwstr_username = proxy_username.c_str();
        if (!WinHttpSetOption(httpRequest, WINHTTP_OPTION_PROXY_USERNAME,
                              const_cast<LPWSTR>(proxy_lpcwstr_username),
                              wcslen(proxy_lpcwstr_username))) {
          error_code = GetLastError();
          EDGE_SDK_LOG_ERROR(
              LOGTAG, "WinHttpSetOption(proxy username) failed " << error_code);
        }

        LPCWSTR proxy_lpcwstr_password = proxy_password.c_str();
        if (!WinHttpSetOption(httpRequest, WINHTTP_OPTION_PROXY_PASSWORD,
                              const_cast<LPWSTR>(proxy_lpcwstr_password),
                              wcslen(proxy_lpcwstr_password))) {
          error_code = GetLastError();
          EDGE_SDK_LOG_ERROR(
              LOGTAG, "WinHttpSetOption(proxy password) failed " << error_code);
        }
      } else {
        if (!username_res) {
          error_code = GetLastError();
          EDGE_SDK_LOG_ERROR(
              LOGTAG, "Proxy username conversion failure " << error_code);
        }
        if (!password_res) {
          error_code = GetLastError();
          EDGE_SDK_LOG_ERROR(
              LOGTAG, "Proxy password conversion failure " << error_code);
        }
      }
    }
  }

  flags = WINHTTP_DECOMPRESSION_FLAG_ALL;
  if (!WinHttpSetOption(httpRequest, WINHTTP_OPTION_DECOMPRESSION, &flags,
                        sizeof(flags)))
    handle->no_compression = true;

  const std::vector<std::pair<std::string, std::string>>& extraHeaders =
      request.GetHeaders();

  std::wostringstream headerStrm;
  _locale_t loc = _create_locale(LC_CTYPE, "C");
  bool foundContentLength = false;
  for (size_t i = 0; i < extraHeaders.size(); i++) {
    std::string headerName = extraHeaders[i].first.c_str();
    std::transform(headerName.begin(), headerName.end(), headerName.begin(),
                   ::tolower);

    if (headerName.compare("content-length") == 0) {
      foundContentLength = true;
    }

    headerStrm << headerName.c_str();
    headerStrm << L": ";
    headerStrm << extraHeaders[i].second.c_str();
    headerStrm << L"\r\n";
  }

  // Set the content-length header if it does not already exist
  if (!foundContentLength) {
    headerStrm << L"content-length: " << contentLength << L"\r\n";
  }

  _free_locale(loc);

  if (!WinHttpAddRequestHeaders(httpRequest, headerStrm.str().c_str(),
                                DWORD(-1), WINHTTP_ADDREQ_FLAG_ADD)) {
    EDGE_SDK_LOG_ERROR(LOGTAG,
                       "WinHttpAddRequestHeaders() failed " << GetLastError());
  }

  /*if (request.ModifiedSince()) {
    FILETIME ft;
    SYSTEMTIME st;
    UnixTimeToFileTime(request.ModifiedSince(), &ft);
    FileTimeToSystemTime(&ft, &st);
    WCHAR pwszTimeStr[WINHTTP_TIME_FORMAT_BUFSIZE / sizeof(WCHAR)];
    if (WinHttpTimeFromSystemTime(&st, pwszTimeStr)) {
      std::wostringstream headerStrm;
      headerStrm << L"If-Modified-Since: ";
      headerStrm << pwszTimeStr;
      if (!WinHttpAddRequestHeaders(httpRequest, headerStrm.str().c_str(),
                                    DWORD(-1), WINHTTP_ADDREQ_FLAG_ADD)) {
        EDGE_SDK_LOG_ERROR(LOGTAG,
                           "WinHttpAddRequestHeaders(if-modified-since) failed "
                               << GetLastError());
      }
    }
  }*/

  /* Send the request */
  if (!WinHttpSendRequest(httpRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                          (LPVOID)content, contentLength, contentLength,
                          (DWORD_PTR)handle.get())) {
    EDGE_SDK_LOG_ERROR(LOGTAG, "WinHttpSendRequest failed " << GetLastError());

    std::unique_lock<std::recursive_mutex> lock(mutex_);

    http_requests_.erase(id);
    // return NetworkProtocol::ErrorIO;
    return NetworkStatus(ErrorCode::IO_ERROR);
  }
  handle->http_request = httpRequest;

  // return NetworkProtocol::ErrorNone;
  return NetworkStatus(id);
}

void NetworkProtocolWinHttp::Cancel(RequestId id) {
  std::unique_lock<std::recursive_mutex> lock(mutex_);
  auto it = http_requests_.find(id);
  if (it == http_requests_.end()) {
    return;
  }

  // Just closing the handle cancels the request
  if (it->second->http_request) {
    WinHttpCloseHandle(it->second->http_request);
    it->second->http_request = NULL;
  }
}

void NetworkProtocolWinHttp::RequestCallback(HINTERNET, DWORD_PTR context,
                                             DWORD status, LPVOID statusInfo,
                                             DWORD statusInfoLength) {
  if (context == NULL) {
    return;
  }

  RequestData* handle = reinterpret_cast<RequestData*>(context);
  if (!handle->connection_data || !handle->result_data) {
    EDGE_SDK_LOG_WARNING(LOGTAG, "RequestCallback to inactive handle");
    return;
  }

  // to extend RequestData lifetime till the end of function
  std::shared_ptr<RequestData> that;

  {
    std::unique_lock<std::recursive_mutex> lock(
        handle->connection_data->self->mutex_);

    that = handle->connection_data->self->http_requests_[handle->request_id];
  }

  handle->connection_data->last_used = GetTickCount64();

  if (status == WINHTTP_CALLBACK_STATUS_REQUEST_ERROR) {
    // Error has occurred
    assert(statusInfoLength == sizeof(WINHTTP_ASYNC_RESULT));
    WINHTTP_ASYNC_RESULT* result =
        reinterpret_cast<WINHTTP_ASYNC_RESULT*>(statusInfo);
    handle->result_data->status = result->dwError;

    if (result->dwError == ERROR_WINHTTP_OPERATION_CANCELLED) {
      handle->result_data->cancelled = true;
    }

    handle->complete();
  } else if (status == WINHTTP_CALLBACK_STATUS_SENDREQUEST_COMPLETE) {
    // We have sent request, now receive a response
    WinHttpReceiveResponse(handle->http_request, NULL);
  } else if (status == WINHTTP_CALLBACK_STATUS_HEADERS_AVAILABLE) {
    Network::HeaderCallback callback = nullptr;
    {
      std::unique_lock<std::recursive_mutex> lock(
          handle->connection_data->self->mutex_);
      if (handle->header_callback) callback = handle->header_callback;
    }

    if (callback && handle->http_request) {
      DWORD wideLen;
      WinHttpQueryHeaders(handle->http_request, WINHTTP_QUERY_RAW_HEADERS,
                          WINHTTP_HEADER_NAME_BY_INDEX,
                          WINHTTP_NO_OUTPUT_BUFFER, &wideLen,
                          WINHTTP_NO_HEADER_INDEX);
      if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        DWORD len = wideLen / sizeof(WCHAR);
        auto wideBuffer = std::make_unique<WCHAR[]>(len);
        if (WinHttpQueryHeaders(handle->http_request, WINHTTP_QUERY_RAW_HEADERS,
                                WINHTTP_HEADER_NAME_BY_INDEX, wideBuffer.get(),
                                &wideLen, WINHTTP_NO_HEADER_INDEX)) {
          // Text should be converted back from the wide char to properly handle
          // UTF-8.
          auto buffer = std::make_unique<char[]>(len);
          int convertResult = WideCharToMultiByte(
              CP_ACP, 0, wideBuffer.get(), len, buffer.get(), len, 0, nullptr);
          assert(convertResult == len);

          DWORD start = 0, index = 0;
          while (index < len) {
            if (buffer[index] == 0) {
              if (start != index) {
                std::string entry(&buffer[start], index - start);
                size_t pos = entry.find(':');
                if (pos != std::string::npos) {
                  std::string key(entry.begin(), entry.begin() + pos);
                  std::string value(entry.begin() + pos + 2, entry.end());
                  callback(key, value);
                }
              }
              index++;
              start = index;
            } else {
              index++;
            }
          }
        }
      }
    }

    {
      std::unique_lock<std::recursive_mutex> lock(
          handle->connection_data->self->mutex_);
      if (handle->http_request) {
        LPWSTR code =
            queryHeadervalue(handle->http_request, WINHTTP_QUERY_STATUS_CODE);
        if (code) {
          std::wstring codeStr(code);
          handle->result_data->status = std::stoi(codeStr);
          LocalFree(code);
        } else {
          handle->result_data->status = -1;
        }

        LPWSTR cache =
            queryHeadervalue(handle->http_request, WINHTTP_QUERY_CACHE_CONTROL);
        if (cache) {
          std::wstring cacheStr(cache);
          std::size_t index = cacheStr.find(L"max-age=");
          if (index != std::wstring::npos)
            handle->result_data->max_age =
                std::stoi(cacheStr.substr(index + 8));
          LocalFree(cache);
        } else {
          handle->result_data->max_age = -1;
        }

        // TODO: expires

        LPWSTR etag =
            queryHeadervalue(handle->http_request, WINHTTP_QUERY_ETAG);
        if (etag) {
          std::wstring etagStr(etag);
          handle->result_data->etag.assign(etagStr.begin(), etagStr.end());
          LocalFree(etag);
        } else {
          handle->result_data->etag.clear();
        }

        LPWSTR date =
            queryHeadervalue(handle->http_request, WINHTTP_QUERY_DATE);
        if (date) {
          handle->date = date;
          LocalFree(date);
        } else {
          handle->date.clear();
        }

        LPWSTR range =
            queryHeadervalue(handle->http_request, WINHTTP_QUERY_CONTENT_RANGE);
        if (range) {
          const std::wstring rangeStr(range);
          const std::size_t index = rangeStr.find(L"bytes ");
          if (index != std::wstring::npos) {
            std::size_t offset = 6;
            if (rangeStr[6] == L'*' && rangeStr[7] == L'/') {
              offset = 8;
            }
            if (handle->resumed) {
              handle->result_data->count =
                  std::stoull(rangeStr.substr(index + offset)) -
                  handle->result_data->offset;
            } else {
              handle->result_data->offset =
                  std::stoull(rangeStr.substr(index + offset));
            }
          }
          LocalFree(range);
        } else {
          handle->result_data->count = 0;
        }

        LPWSTR type =
            queryHeadervalue(handle->http_request, WINHTTP_QUERY_CONTENT_TYPE);
        if (type) {
          std::wstring typeStr(type);
          handle->result_data->content_type.assign(typeStr.begin(),
                                                   typeStr.end());
          LocalFree(type);
        } else {
          handle->result_data->content_type.clear();
        }

        LPWSTR length = queryHeadervalue(handle->http_request,
                                         WINHTTP_QUERY_CONTENT_LENGTH);
        if (length) {
          const std::wstring lengthStr(length);
          handle->result_data->size = std::stoull(lengthStr);
          LocalFree(length);
        } else {
          handle->result_data->size = 0;
        }

        if (handle->no_compression) {
          LPWSTR str = queryHeadervalue(handle->http_request,
                                        WINHTTP_QUERY_CONTENT_ENCODING);
          if (str) {
            std::wstring encoding(str);
            if (encoding == L"gzip") {
#ifdef NETWORK_HAS_ZLIB
              handle->uncompress = true;
              /* allocate inflate state */
              handle->strm.zalloc = Z_NULL;
              handle->strm.zfree = Z_NULL;
              handle->strm.opaque = Z_NULL;
              handle->strm.avail_in = 0;
              handle->strm.next_in = Z_NULL;
              inflateInit2(&handle->strm, 16 + MAX_WBITS);
#else
              EDGE_SDK_LOG_ERROR(
                  LOGTAG,
                  "Gzip encoding but compression no supported and no "
                  "ZLIB found");
#endif
            }
            LocalFree(str);
          }
        }
      } else {
        handle->complete();
        return;
      }
    }

    // We have received headers, now receive data
    WinHttpQueryDataAvailable(handle->http_request, NULL);
  } else if (status == WINHTTP_CALLBACK_STATUS_DATA_AVAILABLE) {
    assert(statusInfoLength == sizeof(DWORD));
    DWORD size = *reinterpret_cast<DWORD*>(statusInfo);
    if (size > 0 && 416 != handle->result_data->status) {
      // Data is available read it
      LPVOID buffer = (LPVOID)LocalAlloc(LPTR, size);
      if (!buffer) {
        EDGE_SDK_LOG_ERROR(LOGTAG,
                           "Out of memory reeceiving " << size << " bytes");
        handle->result_data->status = ERROR_NOT_ENOUGH_MEMORY;
        handle->complete();
        return;
      }
      WinHttpReadData(handle->http_request, buffer, size, NULL);
    } else {
      // Request is complete
      if (handle->result_data->status != 416) {
        // Skip size check if manually decompressing, since it's known to not
        // match.
        if (!handle->ignore_data && !handle->uncompress &&
            handle->result_data->size != 0 &&
            handle->result_data->size != handle->result_data->count) {
          handle->result_data->status = -1;
        }
      }
      handle->result_data->completed = true;
      handle->complete();
    }
  } else if (status == WINHTTP_CALLBACK_STATUS_READ_COMPLETE) {
    // Read is complete, check if there is more
    if (statusInfo && statusInfoLength) {
      const char* dataBuffer = (const char*)statusInfo;
      DWORD dataLen = statusInfoLength;
#ifdef NETWORK_HAS_ZLIB
      if (handle->uncompress) {
        Bytef* compressed = (Bytef*)statusInfo;
        DWORD compressedLen = dataLen;
        dataBuffer =
            (const char*)LocalAlloc(LPTR, kNetworkUncompressionChunkSize);
        handle->strm.avail_in = compressedLen;
        handle->strm.next_in = compressed;
        dataLen = 0;
        DWORD allocSize = kNetworkUncompressionChunkSize;

        while (handle->strm.avail_in > 0) {
          handle->strm.next_out = (Bytef*)dataBuffer + dataLen;
          DWORD availableSize = allocSize - dataLen;
          handle->strm.avail_out = availableSize;
          int r = inflate(&handle->strm, Z_NO_FLUSH);

          if ((r != Z_OK) && (r != Z_STREAM_END)) {
            EDGE_SDK_LOG_ERROR(LOGTAG, "Uncompression failed");
            LocalFree((HLOCAL)compressed);
            LocalFree((HLOCAL)dataBuffer);
            handle->result_data->status = ERROR_INVALID_BLOCK;
            handle->complete();
            return;
          }

          dataLen += availableSize - handle->strm.avail_out;
          if (r == Z_STREAM_END) break;

          if (dataLen == allocSize) {
            // We ran out of space in uncompression buffer, expand the buffer
            // and loop again
            allocSize += kNetworkUncompressionChunkSize;
            char* newBuffer = (char*)LocalAlloc(LPTR, allocSize);
            memcpy(newBuffer, dataBuffer, dataLen);
            LocalFree((HLOCAL)dataBuffer);
            dataBuffer = (const char*)newBuffer;
          }
        }
        LocalFree((HLOCAL)compressed);
      }
#endif

      if (dataLen) {
        std::uint64_t totalOffset = 0;

        if (handle->data_callback)
          handle->data_callback((const uint8_t*)dataBuffer, totalOffset,
                                dataLen);

        {
          std::unique_lock<std::recursive_mutex> lock(
              handle->connection_data->self->mutex_);
          if (handle->payload) {
            // if (!handle->ignoreOffset) {
            if (handle->payload->tellp() !=
                std::streampos(handle->result_data->count)) {
              handle->payload->seekp(handle->result_data->count);
              if (handle->payload->fail()) {
                EDGE_SDK_LOG_WARNING(
                    LOGTAG,
                    "Reception stream doesn't support setting write point");
                handle->payload->clear();
              }
            }
            //}

            handle->payload->write(dataBuffer, dataLen);
          }
          handle->result_data->count += dataLen;
        }
      }
      LocalFree((HLOCAL)dataBuffer);
    }

    WinHttpQueryDataAvailable(handle->http_request, NULL);
  } else if (status == WINHTTP_CALLBACK_STATUS_HANDLE_CLOSING) {
    // Only now is it safe to free the handle
    // See
    // https://docs.microsoft.com/en-us/windows/desktop/api/winhttp/nf-winhttp-winhttpclosehandle
    handle->freeHandle();
    return;
  } else {
    EDGE_SDK_LOG_ERROR(LOGTAG,
                       "Unknown callback " << std::hex << status << std::dec);
  }
}

DWORD
NetworkProtocolWinHttp::Run(LPVOID arg) {
  reinterpret_cast<NetworkProtocolWinHttp*>(arg)->CompletionThread();
  return 0;
}

void NetworkProtocolWinHttp::CompletionThread() {
  std::shared_ptr<NetworkProtocolWinHttp> that = shared_from_this();

  while (that->http_session_) {
    std::shared_ptr<ResultData> result;
    {
      if (http_session_ && results_.empty()) {
        WaitForSingleObject(event_, 30000);  // Wait max 30 seconds
        ResetEvent(event_);
      }
      if (!http_session_) continue;

      std::unique_lock<std::recursive_mutex> lock(mutex_);
      if (!results_.empty()) {
        result = results_.front();
        results_.pop();
      }
    }

    if (http_session_ && result) {
      std::string str;
      int status;
      if ((result->offset == 0) && (result->status == 206))
        result->status = 200;

      if (result->completed)
        str =
            "todo: convert http code to string";  // NetworkProtocol::HttpErrorToString(result->status);
      else
        str = errorToString(result->status);

      if (result->completed)
        status = result->status;
      else
        status = static_cast<int>(errorToCode(result->status));
      // NetworkResponse response(
      //    result->id, result->cancelled, status, str, result->maxAge,
      //    result->expires, result->etag, result->contentType,
      //    result->count, result->offset, result->payload,
      //    std::move(result->statistics));
      NetworkResponse response = NetworkResponse()
                                     .WithCancelled(result->cancelled)
                                     .WithError(str)
                                     .WithRequestId(result->request_id)
                                     .WithStatus(status);
      if (result->user_callback) {
        Network::Callback callback = nullptr;
        {
          std::lock_guard<std::recursive_mutex> lock(mutex_);
          // protect against multiple calls
          std::swap(result->user_callback, callback);
        }
        // must call outside lock to prevent deadlock
        callback(std::move(response));
      }
    }
    if (http_session_ && !http_connections_.empty()) {
      // Check for timeouted connections
      std::unique_lock<std::recursive_mutex> lock(mutex_);
      std::vector<std::wstring> closed;
      for (const std::pair<std::wstring, std::shared_ptr<ConnectionData>>&
               conn : http_connections_) {
        if ((GetTickCount64() - conn.second->last_used) > (1000 * 60 * 5)) {
          // This connection has not been used in 5 minutes
          closed.push_back(conn.first);
        }
      }
      for (const std::wstring& conn : closed) http_connections_.erase(conn);
    }
  }
}

NetworkProtocolWinHttp::ResultData::ResultData(
    RequestId id, Network::Callback callback,
    std::shared_ptr<std::ostream> payload)
    : user_callback(callback),
      payload(payload),
      size(0),
      count(0),
      offset(0),
      request_id(id),
      status(-1),
      max_age(-1),
      expires(-1),
      completed(false),
      cancelled(false) {}

NetworkProtocolWinHttp::ConnectionData::ConnectionData(
    const std::shared_ptr<NetworkProtocolWinHttp>& owner)
    : self(owner), http_connection(NULL) {}

NetworkProtocolWinHttp::ConnectionData::~ConnectionData() {
  if (http_connection) {
    WinHttpCloseHandle(http_connection);
    http_connection = NULL;
  }
}

NetworkProtocolWinHttp::RequestData::RequestData(
    RequestId id, std::shared_ptr<ConnectionData> connection,
    Network::Callback callback, Network::HeaderCallback header_callback,
    Network::DataCallback data_callback, std::shared_ptr<std::ostream> payload,
    const NetworkRequest& request)
    : connection_data(connection),
      result_data(new ResultData(id, callback, payload)),
      payload(payload),
      header_callback(header_callback),
      data_callback(data_callback),
      http_request(NULL),
      request_id(id),
      resumed(false),
      // ignoreOffset(false),
      ignore_data(request.GetVerb() == NetworkRequest::HttpVerb::HEAD),
      // getStatistics(false),
      no_compression(false),
      uncompress(false) {}

NetworkProtocolWinHttp::RequestData::~RequestData() {
  if (http_request) {
    WinHttpCloseHandle(http_request);
    http_request = NULL;
  }
}

void NetworkProtocolWinHttp::RequestData::complete() {
  std::shared_ptr<NetworkProtocolWinHttp> that = connection_data->self;
  {
    std::unique_lock<std::recursive_mutex> lock(that->mutex_);
    that->results_.push(result_data);
  }
  SetEvent(that->event_);
}

void NetworkProtocolWinHttp::RequestData::freeHandle() {
  std::shared_ptr<NetworkProtocolWinHttp> that = connection_data->self;
  {
    std::unique_lock<std::recursive_mutex> lock(that->mutex_);
    that->http_requests_.erase(request_id);
  }
}

}  // namespace network2
}  // namespace olp
