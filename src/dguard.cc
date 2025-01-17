#include <napi.h>
#include <mutex>
#include "agent.h"

namespace dguard {
    class FunctionPromiseWorker final : public Napi::AsyncWorker {
    private:
        Napi::Promise::Deferred deferred;
        std::mutex mutex;
        std::function<std::string()> executor;
        std::string result;  // 결과를 저장할 멤버 변수

    public:
        explicit FunctionPromiseWorker(const Napi::Promise::Deferred& deferred, std::function<std::string()> executor)
            : AsyncWorker(deferred.Env()), // napi async worker 상속
              deferred(deferred),
              executor(std::move(executor)) {}

        // Execute는 워커 스레드에서 실행됩니다
        void Execute() override {
            std::lock_guard<std::mutex> lock(mutex);
            // 실제 비동기 작업이 여기서 수행됩니다
            result = executor();
            // 여기서 발생하는 예외는 OnError로 자동 전달됩니다
        }

        // OnOK는 메인 스레드(이벤트 루프)에서 실행됩니다
        void OnOK() override {
            Napi::HandleScope scope(Env());
            std::lock_guard<std::mutex> lock(mutex);

            // V8/Node.js 객체 생성은 반드시 메인 스레드에서 해야 합니다
            deferred.Resolve(Napi::String::New(Env(), result));
        }

        void OnError(const Napi::Error& e) override {
            Napi::HandleScope scope(Env());
            std::lock_guard<std::mutex> lock(mutex);
            deferred.Reject(e.Value());
        }
    };

    // 메인 스레드에서만 실행
    Napi::Value Encrypt(const Napi::CallbackInfo& info) {
        Napi::Env env = info.Env();

        // 파라미터 검증
        if (info.Length() != 3 || !info[0].IsString() || !info[1].IsString() || !info[2].IsString()) {
            Napi::TypeError::New(env, "String expected").ThrowAsJavaScriptException();
            return env.Undefined();
        }

        // 파라미터 가져오기
        const std::string tableName = info[0].As<Napi::String>().Utf8Value();
        const std::string columnName = info[1].As<Napi::String>().Utf8Value();
        const std::string input = info[2].As<Napi::String>().Utf8Value();

        auto deferredEncrypt = [=]() {
            return Agent::Encrypt(tableName.c_str(), columnName.c_str(), input.c_str());
        };

        // Promise 생성
        Napi::Promise::Deferred deferred = Napi::Promise::Deferred::New(env);

        auto* worker = new FunctionPromiseWorker(deferred, deferredEncrypt);
        // 비동기 작업 큐에 보냄
        worker->Queue();

        return deferred.Promise();
    }

    Napi::Value Decrypt(const Napi::CallbackInfo& info) {
        Napi::Env env = info.Env();

        // 파라미터 검증
        if (info.Length() != 3 || !info[0].IsString() || !info[1].IsString() || !info[2].IsString()) {
            Napi::TypeError::New(env, "String expected").ThrowAsJavaScriptException();
            return env.Undefined();
        }

        // 파라미터 가져오기
        const std::string tableName = info[0].As<Napi::String>().Utf8Value();
        const std::string columnName = info[1].As<Napi::String>().Utf8Value();
        const std::string input = info[2].As<Napi::String>().Utf8Value();

        auto deferredDecrypt = [=]() {
            return Agent::Decrypt(tableName.c_str(), columnName.c_str(), input.c_str());
        };

        // Promise 생성
        Napi::Promise::Deferred deferred = Napi::Promise::Deferred::New(env);

        auto* worker = new FunctionPromiseWorker(deferred, deferredDecrypt);
        // 비동기 작업 큐에 보냄
        worker->Queue();

        return deferred.Promise();
    }

    Napi::Value Hash(const Napi::CallbackInfo& info) {
        Napi::Env env = info.Env();

        // 파라미터 검증
        if (info.Length() != 3 || !info[0].IsString() || !info[1].IsString() || !info[2].IsString()) {
            Napi::TypeError::New(env, "String expected").ThrowAsJavaScriptException();
            return env.Undefined();
        }

        // 파라미터 가져오기
        const std::string tableName = info[0].As<Napi::String>().Utf8Value();
        const std::string columnName = info[1].As<Napi::String>().Utf8Value();
        const std::string input = info[2].As<Napi::String>().Utf8Value();

        auto deferredHash = [=]() {
            return Agent::Hash(tableName.c_str(), columnName.c_str(), input.c_str());
        };

        // Promise 생성
        Napi::Promise::Deferred deferred = Napi::Promise::Deferred::New(env);

        auto* worker = new FunctionPromiseWorker(deferred, deferredHash);
        // 비동기 작업 큐에 보냄
        worker->Queue();

        return deferred.Promise();
    }

    Napi::Value Init(const Napi::CallbackInfo& info) {
        try {
            Agent::Init();
        } catch (const std::exception& e) {
            Napi::Error::New(info.Env(), e.what()).ThrowAsJavaScriptException();
        }
        return info.Env().Undefined();
    }

    Napi::Value Close(const Napi::CallbackInfo& info) {
        try {
            Agent::Close();
        } catch (const std::exception& e) {
            Napi::Error::New(info.Env(), e.what()).ThrowAsJavaScriptException();
        }
        return info.Env().Undefined();
    }

    Napi::Object DGuard(Napi::Env env, Napi::Object exports) {
        exports.Set(Napi::String::New(env, "init"), Napi::Function::New(env, Init));
        exports.Set(Napi::String::New(env, "close"), Napi::Function::New(env, Close));
        exports.Set(Napi::String::New(env, "encrypt"), Napi::Function::New(env, Encrypt));
        exports.Set(Napi::String::New(env, "decrypt"), Napi::Function::New(env, Decrypt));
        exports.Set(Napi::String::New(env, "hash"), Napi::Function::New(env, Hash));
        return exports;
    }

    NODE_API_MODULE(dguard, DGuard);
}
