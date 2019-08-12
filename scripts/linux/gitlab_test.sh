#!/bin/bash -xe
#CPP_SOURCE_AUTHENTICATION=build/olp-cpp-sdk-authentication
CPP_TEST_SOURCE_AUTHENTICATION=build/olp-cpp-sdk-authentication/test
#CPP_SOURCE_CORE=build/olp-cpp-sdk-core
CPP_TEST_SOURCE_CORE=build/olp-cpp-sdk-core/tests
#CPP_SOURCE_DATASERVICE_READ=build/olp-cpp-sdk-dataservice-read/examples
CPP_TEST_SOURCE_DATASERVICE_READ=build/olp-cpp-sdk-dataservice-read/test
#CPP_SOURCE_DATASERVICE_WRITE=build/olp-cpp-sdk-dataservice-write
CPP_TEST_SOURCE_DATASERVICE_WRITE=build/olp-cpp-sdk-dataservice-write/test
set +e
echo ">>> Authentication Test ... >>>"
$CPP_TEST_SOURCE_AUTHENTICATION/unit/olp-authentication-test --gtest_output="xml:report.xml"
echo ">>> Core - Cache Test ... >>>"
$CPP_TEST_SOURCE_CORE/cache/cache-test --gtest_output="xml:report1.xml"
echo ">>> Core - Geo Test ... >>>"
$CPP_TEST_SOURCE_CORE/geo/geo-test --gtest_output="xml:report2.xml"
echo ">>> Core - Network Test ... >>>"
$CPP_TEST_SOURCE_CORE/network/olp-core-network-test --gtest_output="xml:report3.xml" --gtest_filter="*Offline*:*offline*"
echo ">>> Core - SOURCE DATASERVICE READ Test ... >>>"
$CPP_TEST_SOURCE_DATASERVICE_READ/unit/olp-dataservice-read-test --gtest_output="xml:report4.xml" --gtest_filter=-*Online* --endpoint=https://account.api.here.com/oauth2/token --catalog=hrn:here:data:::hereos-internal-test-v2 --appid=${appid} --secret=${secret}
echo ">>> Core - SOURCE DATASERVICE WRITE Test ... >>>"
$CPP_TEST_SOURCE_DATASERVICE_WRITE/olp-dataservice-write-test --gtest_output="xml:report5.xml" --gtest_filter=-*Online* --endpoint=https://account.api.here.com/oauth2/token --catalog=hrn:here:data:::olp-cpp-sdk-ingestion-test-catalog --layer=olp-cpp-sdk-ingestion-test-stream-layer --layer2=olp-cpp-sdk-ingestion-test-stream-layer-2 --layer-sdii=olp-cpp-sdk-ingestion-test-stream-layer-sdii --versioned-layer=olp-cpp-sdk-ingestion-test-versioned-layer --volatile-layer=olp-cpp-sdk-ingestion-test-volatile-layer --index-layer=olp-cpp-sdk-ingestion-test-index-layer --appid=${appid} --secret=${secret}       
set -e
