cmd_Release/obj.target/addon/addon.o := g++ -o Release/obj.target/addon/addon.o ../addon.cc '-DNODE_GYP_MODULE_NAME=addon' '-DUSING_UV_SHARED=1' '-DUSING_V8_SHARED=1' '-DV8_DEPRECATION_WARNINGS=1' '-D_GLIBCXX_USE_CXX11_ABI=1' '-D_LARGEFILE_SOURCE' '-D_FILE_OFFSET_BITS=64' '-D__STDC_FORMAT_MACROS' '-DOPENSSL_NO_PINSHARED' '-DOPENSSL_THREADS' '-DBUILDING_NODE_EXTENSION' -I/home/dguard/.cache/node-gyp/20.18.1/include/node -I/home/dguard/.cache/node-gyp/20.18.1/src -I/home/dguard/.cache/node-gyp/20.18.1/deps/openssl/config -I/home/dguard/.cache/node-gyp/20.18.1/deps/openssl/openssl/include -I/home/dguard/.cache/node-gyp/20.18.1/deps/uv/include -I/home/dguard/.cache/node-gyp/20.18.1/deps/zlib -I/home/dguard/.cache/node-gyp/20.18.1/deps/v8/include  -fPIC -pthread -Wall -Wextra -Wno-unused-parameter -m64 -O3 -fno-omit-frame-pointer -fno-rtti -fno-exceptions -std=gnu++17 -MMD -MF ./Release/.deps/Release/obj.target/addon/addon.o.d.raw   -c
Release/obj.target/addon/addon.o: ../addon.cc \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/node.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/v8.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/cppgc/common.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/v8config.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/v8-array-buffer.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/v8-local-handle.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/v8-internal.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/v8-version.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/v8config.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/v8-object.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/v8-maybe.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/v8-persistent-handle.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/v8-weak-callback-info.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/v8-primitive.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/v8-data.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/v8-value.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/v8-traced-handle.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/v8-container.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/v8-context.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/v8-snapshot.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/v8-date.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/v8-debug.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/v8-script.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/v8-callbacks.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/v8-promise.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/v8-message.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/v8-exception.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/v8-extension.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/v8-external.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/v8-function.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/v8-function-callback.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/v8-template.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/v8-memory-span.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/v8-initialization.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/v8-isolate.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/v8-embedder-heap.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/v8-microtask.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/v8-statistics.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/v8-unwinder.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/v8-embedder-state-scope.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/v8-platform.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/v8-json.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/v8-locker.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/v8-microtask-queue.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/v8-primitive-object.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/v8-proxy.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/v8-regexp.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/v8-typed-array.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/v8-value-serializer.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/v8-wasm.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/node_version.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/node_api.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/js_native_api.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/js_native_api_types.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/node_api_types.h \
 /home/dguard/.cache/node-gyp/20.18.1/include/node/v8.h
../addon.cc:
/home/dguard/.cache/node-gyp/20.18.1/include/node/node.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/v8.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/cppgc/common.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/v8config.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/v8-array-buffer.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/v8-local-handle.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/v8-internal.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/v8-version.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/v8config.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/v8-object.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/v8-maybe.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/v8-persistent-handle.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/v8-weak-callback-info.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/v8-primitive.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/v8-data.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/v8-value.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/v8-traced-handle.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/v8-container.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/v8-context.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/v8-snapshot.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/v8-date.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/v8-debug.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/v8-script.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/v8-callbacks.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/v8-promise.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/v8-message.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/v8-exception.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/v8-extension.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/v8-external.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/v8-function.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/v8-function-callback.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/v8-template.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/v8-memory-span.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/v8-initialization.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/v8-isolate.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/v8-embedder-heap.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/v8-microtask.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/v8-statistics.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/v8-unwinder.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/v8-embedder-state-scope.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/v8-platform.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/v8-json.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/v8-locker.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/v8-microtask-queue.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/v8-primitive-object.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/v8-proxy.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/v8-regexp.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/v8-typed-array.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/v8-value-serializer.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/v8-wasm.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/node_version.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/node_api.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/js_native_api.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/js_native_api_types.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/node_api_types.h:
/home/dguard/.cache/node-gyp/20.18.1/include/node/v8.h: