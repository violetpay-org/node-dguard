#include <node.h>
#include <v8.h>
#include <dlfcn.h>  // Linux/MacOS용 (Windows에서는 <windows.h> 사용)
#include <string>
#include <cstring>  // C 스타일 문자열 처리
#include <mutex>     // 쓰레드 안전성 확보

namespace demo {
  using v8::FunctionCallbackInfo;
  using v8::Isolate;
  using v8::Local;
  using v8::Object;
  using v8::String;
  using v8::Value;

  // 전역 변수
    void* g_library_handle = nullptr;  // 전역 라이브러리 핸들
    std::mutex g_library_mutex;       // 쓰레드 안전성을 위한 뮤텍스

  typedef char*  (*dg_encryptFunc)(const char*, const char*, const char*, char*);  // C 함수 포인터 선언
  typedef char*  (*dg_decryptFunc)(const char*, const char*, const char*, char*);  // C 함수 포인터 선언
  typedef char*  (*dg_hashFunc)(const char*, const char*, const char*, char*);  // C 함수 포인터 선언

    std::string BuildLibraryPath(const char* base_path, const char* sub_path) {
        std::string full_path(base_path);
        if (full_path.back() != '/') {
            full_path += '/';
        }
        full_path += sub_path;
        return full_path;
    }

    // 라이브러리 초기화 함수
    bool InitializeLibrary() {
        std::lock_guard<std::mutex> lock(g_library_mutex);  // 쓰레드 안전성을 보장
        if (g_library_handle == nullptr) {
	    const char* lib_path_env = std::getenv("EAP_HOME");
	    if (!lib_path_env) {
                return false;  // 환경변수가 설정되지 않은 경우
            }
            // 세부 경로 추가
            std::string lib_path = BuildLibraryPath(lib_path_env, "lib/libDGuardAPI.so");

            g_library_handle = dlopen(lib_path.c_str(), RTLD_LAZY);
            if (!g_library_handle) {
                return false;  // 로드 실패
            }
        }
        return true;
    }

    // 라이브러리 언로드 함수
    void UnloadLibrary() {
        std::lock_guard<std::mutex> lock(g_library_mutex);
        if (g_library_handle != nullptr) {
            dlclose(g_library_handle);
            g_library_handle = nullptr;
        }
    }

  // 문자열을 받아 암호화하는 함수
  void Encrypt(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    // 파라미터 검증
    if (args.Length() < 3 || !args[0]->IsString() || !args[1]->IsString() || !args[2]->IsString()) {
        isolate->ThrowException(String::NewFromUtf8(isolate, "Expected three string arguments").ToLocalChecked());
        return;
    }

    // 라이브러리 초기화
    if (!InitializeLibrary()) {
        isolate->ThrowException(String::NewFromUtf8(isolate, "Failed to load library").ToLocalChecked());
        return;
    }

    dg_encryptFunc dg_encrypt = (dg_encryptFunc)dlsym(g_library_handle, "dg_encrypt");
    if (!dg_encrypt) {
            isolate->ThrowException(String::NewFromUtf8(isolate, "Failed to load function").ToLocalChecked());
            return;
    }

    // 각 문자열 파라미터 가져오기
    v8::String::Utf8Value str1(isolate, args[0]);
    v8::String::Utf8Value str2(isolate, args[1]);
    v8::String::Utf8Value str3(isolate, args[2]);

    std::string table_str = std::string(*str1);
    std::string col_str = std::string(*str2);
    std::string input = std::string(*str3);

    char* result = new char[5000];

    // 문자열 처리 로직
    dg_encrypt(table_str.c_str(), col_str.c_str(), input.c_str(), result);
    //std::string result = "Processed: [" + table_str + "] [" + col_str + "] [" + input + "]";

    // 결과 반환
    args.GetReturnValue().Set(String::NewFromUtf8(isolate, result).ToLocalChecked());

    delete[] result;

  }

  // 문자열을 받아 복호화하는 함수
  void Decrypt(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    // 파라미터 검증
    if (args.Length() < 3 || !args[0]->IsString() || !args[1]->IsString() || !args[2]->IsString()) {
        isolate->ThrowException(String::NewFromUtf8(isolate, "Expected three string arguments").ToLocalChecked());
        return;
    }

    // 라이브러리 초기화
    if (!InitializeLibrary()) {
        isolate->ThrowException(String::NewFromUtf8(isolate, "Failed to load library").ToLocalChecked());
        return;
    }

    dg_decryptFunc dg_decrypt = (dg_decryptFunc)dlsym(g_library_handle, "dg_decrypt");
    if (!dg_decrypt) {
            isolate->ThrowException(String::NewFromUtf8(isolate, "Failed to load function").ToLocalChecked());
            return;
    }

    // 각 문자열 파라미터 가져오기
    v8::String::Utf8Value str1(isolate, args[0]);
    v8::String::Utf8Value str2(isolate, args[1]);
    v8::String::Utf8Value str3(isolate, args[2]);

    std::string table_str = std::string(*str1);
    std::string col_str = std::string(*str2);
    std::string input = std::string(*str3);

    char* result = new char[5000];

    // 문자열 처리 로직
    dg_decrypt(table_str.c_str(), col_str.c_str(), input.c_str(), result);

    // 결과 반환
    args.GetReturnValue().Set(String::NewFromUtf8(isolate, result).ToLocalChecked());

    delete[] result;

  }

  // 문자열을 받아 해쉬하는 함수
  void Hash(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();

    // 파라미터 검증
    if (args.Length() < 3 || !args[0]->IsString() || !args[1]->IsString() || !args[2]->IsString()) {
        isolate->ThrowException(String::NewFromUtf8(isolate, "Expected three string arguments").ToLocalChecked());
        return;
    }

    // 라이브러리 초기화
    if (!InitializeLibrary()) {
        isolate->ThrowException(String::NewFromUtf8(isolate, "Failed to load library").ToLocalChecked());
        return;
    }

    dg_hashFunc dg_hash = (dg_hashFunc)dlsym(g_library_handle, "dg_hash");
    if (!dg_hash) {
            isolate->ThrowException(String::NewFromUtf8(isolate, "Failed to load function").ToLocalChecked());
            return;
    }

    // 각 문자열 파라미터 가져오기
    v8::String::Utf8Value str1(isolate, args[0]);
    v8::String::Utf8Value str2(isolate, args[1]);
    v8::String::Utf8Value str3(isolate, args[2]);

    std::string table_str = std::string(*str1);
    std::string col_str = std::string(*str2);
    std::string input = std::string(*str3);

    char* result = new char[5000];

    // 문자열 처리 로직
    dg_hash(table_str.c_str(), col_str.c_str(), input.c_str(), result);

    // 결과 반환
    args.GetReturnValue().Set(String::NewFromUtf8(isolate, result).ToLocalChecked());

    delete[] result;

  }

  // Node.js 모듈 종료 시 라이브러리 언로드
  void FinalizeModule(void*) {
     UnloadLibrary();
  }

  void Initialize(Local<Object> exports) {
    NODE_SET_METHOD(exports, "Encrypt", Encrypt);
    NODE_SET_METHOD(exports, "Decrypt", Decrypt);
    NODE_SET_METHOD(exports, "Hash", Hash);
  }

  NODE_MODULE(NODE_GYP_MODULE_NAME, Initialize)
}  // namespace demo
