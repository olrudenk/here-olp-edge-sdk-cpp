# Write example

This example shows how to write your own data to OLP stream layer using the HERE OLP Edge SDK C++.

Before you run the example, you have to replace the placeholders in `examples/dataservice-write/example.cpp` with your app key, app secret, catalog HRN and layer:

```cpp
const std::string gKeyId("");            // your here.access.key.id
const std::string gKeySecret("");        // your here.access.key.secret
const std::string gCatalogHRN("");       // your catalog HRN where to write to
const std::string gLayer("");            // layer name inside catalog to use
```

## Building and running on Linux

Configure the project with `EDGE_SDK_BUILD_EXAMPLES` set to `ON` to enabled examples `CMake` targets:

```bash
mkdir build && cd build
cmake -DEDGE_SDK_BUILD_EXAMPLES=ON ..
```

To build the example, run the following command in the `build` folder:

```bash
cmake --build . --target dataservice-write-example
```

To execute the example, run:

```bash
./examples/dataservice-write/dataservice-write-example
```

If everything is fine, you would see `Publish Successful - TraceID: <TraceId generated by the platform>`.

## Building and running on Android

This example shows how to integrate and use the HERE OLP Edge SDK C++ in an Android project.

### Prerequisites

* Setup the Android environment.
* Provide correct keyId, secret key, and other information stated at the beginning of this README file.

### Build HERE OLP Edge SDK C++

First, before building, you need to configure the SDK with `EDGE_SDK_BUILD_EXAMPLES` set to `ON`, the path to Android NDK's toolchain file set via the `CMAKE_TOOLCHAIN_FILE` variable, and, optionally, the [NDK-specific CMake variables](https://developer.android.com/ndk/guides/cmake#variables).

```bash
mkdir build && cd build
cmake .. -DEDGE_SDK_BUILD_EXAMPLES=ON -DCMAKE_TOOLCHAIN_FILE=$NDK_ROOT/build/cmake/android.toolchain.cmake -DANDROID_ABI=arm64-v8a
```

The `CMake` command will generate a `Gradle` project in the `build/examples/dataservice-write/android` folder. Before it can be used, you have to install the HERE OLP Edge SDK C++ libraries into the sysroot directory:

```bash
# Execute as sudo if necessary
(sudo) make install
```

### Assemble APK and run it on Android device

Now, the `Gradle` project is configured, and you can use the `gradlew` executable to build and install the apk on your Android device:

```bash
cd examples/dataservice-write/android
./gradlew assembleDebug
./gradlew installDebug
```

Alternatively, you can use the Android Studio IDE by opening the `build/examples/dataservice-write/android/build.gradle` script.

After installing and running the `dataservice_write_example` apk, you should see the `Publish Successful` message in the main UI screen if you correctly setup keyId, secretKey, catalog, and layer information. If you encountered an error, please check the device's logcat for the error message.

### Additional notes

Note, that you can run `CMake` command directly from `<olp-edge-sdk-root>/examples/dataservice-write/` folder if you have already built and installed HERE OLP Edge SDK C++ libraries for Android. Make sure that you pass the correct path to `LevelDB` library and provided the correct `EDGE_SDK_NETWORK_PROTOCOL_JAR` parameter in the `CMake` command invoked by the `build/examples/dataservice-write/android/app/build.gradle` script.

## Building and running on iOS

This example shows how to integrate and use the HERE OLP Edge SDK C++ in a basic iOS application written in Objective-C language.

### Prerequisites

* Setup the iOS development environment - install the `XCode` and command line tools.
* Install external dependencies - refer to the `README.md` file located under `<olp-edge-sdk-root>/README.md`.
* Provide correct keyId, secret key, and other information stated at the beginning of this README file.

### Build HERE OLP Edge SDK C++

First, before building, you need to configure the HERE OLP Edge SDK C++ with `EDGE_SDK_BUILD_EXAMPLES` set to `ON`, (optionally) disable tests with `EDGE_SDK_ENABLE_TESTING` set to `OFF`, and specify the path to the iOS toolchain file shipped together with the SDK and located under `<olp-edge-sdk-root>/cmake/toolchains/iOS.cmake`:

```bash
mkdir build && cd build
cmake .. -GXcode  -DCMAKE_TOOLCHAIN_FILE=../cmake/toolchains/iOS.cmake -DPLATFORM=iphoneos -DEDGE_SDK_BUILD_EXAMPLES=ON -DEDGE_SDK_ENABLE_TESTING=OFF
```

Note that in order to configure the HERE OLP Edge SDK C++ for a simulator, you need to set the `SIMULATOR` variable to `ON`.

### Build and run the application on the device

Now open the generated `XCode` project:
```bash
open olp-cpp-sdk.xcodeproj
```

Select the `dataservice-write-example` scheme from the schemes list in the `XCode` project and specify your signing credentials for the `dataservice-write-example` target.

Once everything is correctly set up, build and run the example application on your device and you should see the `Publish Successful` message in the main UI screen. If you encountered an error message, e.g. `Publish Failed`, please check the device's logs for the detailed description of the error.

## How it works

### StreamLayerClient

The `StreamLayerClient` class provides an interface for the ingestion of OLP data, and defines the following operations:

* `PublishData`: Publish data into an OLP stream layer.
* `PublishSdii`: Publish list of SDII messages into an OLP stream layer.

To create a `StreamLayerClient` provide the corresponding HRN and a preconfigured `OlpClientSettings`:

```cpp
// Setup AuthenticationSettings with a default token provider that will
// retrieve an OAuth 2.0 token from OLP.
olp::client::AuthenticationSettings authSettings;
authSettings.provider =
    olp::authentication::TokenProviderDefault(gKeyId, gKeySecret);

// Setup OlpClientSettings and provide it to the StreamLayerClient.
olp::client::OlpClientSettings clientSettings;
clientSettings.authentication_settings = authSettings;

auto client = std::make_shared<StreamLayerClient>(
    olp::client::HRN{gCatalogHRN}, clientSettings);
```

The `StreamLayerClient` class pulls together all the different settings which can be used to customize the behavior of the client.

* `retry_settings`: Sets the `olp::client::RetrySettings` to be used.
* `proxy_settings`: Sets the `olp::authentication::NetworkProxySettings` to be used.
* `authentication_settings`: Sets the `olp::client::AuthenticationSettings` to be used.
* `network_async_handler`: Sets the handler for asynchronous execution of network requests.

For basic usage, we need to specify only `authentication_settings`.

### Publish data into stream layer

To publish data into stream layer you to create `PublishDataRequest`. The `PublishDataRequest` class is used to specify the parameters of the `PublishData` function, including the following:

* `WithData`: Specify the data to be uploaded to the layer.
* `WithLayerId`: Specify the stream layer to upload data to.
* `WithTraceId`: Set the trace id for the request.
* `WithBillingTag`: Set the billing tag for the request.
* `WithChecksum`: Set the checksum for the partition.

```cpp
// Create a publish data request
auto request = PublishDataRequest().WithData(buffer).WithLayerId(gLayer);
```

Then pass it to the `StreamLayerClient` via `PublishData` method:

```cpp
// Write data to OLP Stream Layer using StreamLayerClient
auto futureResponse = client->PublishData(request);
```

The execution result is a `CancellableFuture` that contains `PublishDataResponse` object. The `PublishDataResponse` class holds details of the completed operation, and should be used to determine operation success and access resultant data.

* `IsSuccessful`: Returns true if this response is considered successful, false otherwise.
* `GetResult`: Returns the resultant data (`olp::dataservice::write::PublishDataResult`) in the case that the operation is successful.
* `GetError`: Contains information about the error that occurred in the case of error in a `olp::client::ApiError` object.

The `PublishDataResult` class returns details of the request result, including:

* `GetTraceID`: Get the trace id of the request.

```cpp
// Wait for response
auto response = futureResponse.GetFuture().get();

// Check the response
if (!response.IsSuccessful()) {
    EDGE_SDK_LOG_INFO_F("write-example",
                        "Error writing data - HTTP Status: %d Message: %s",
                        response.GetError().GetHttpStatusCode(),
                        response.GetError().GetMessage().c_str());
    return -1;
} else {
    EDGE_SDK_LOG_ERROR_F("write-example", "Publish Successful - TraceID: %s",
                         response.GetResult().GetTraceID().c_str());
}
```
