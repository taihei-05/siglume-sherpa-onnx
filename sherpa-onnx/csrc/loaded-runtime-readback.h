// Candidate loaded-runtime evidence for the existing Windows/macOS CPU backend.
#ifndef SHERPA_ONNX_CSRC_LOADED_RUNTIME_READBACK_H_
#define SHERPA_ONNX_CSRC_LOADED_RUNTIME_READBACK_H_

#include <algorithm>
#include <array>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>
#include "nlohmann/json.hpp"
#include "onnxruntime_cxx_api.h"
#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#elif defined(__APPLE__)
#include <CommonCrypto/CommonDigest.h>
#else
#error "The loaded-runtime candidate supports Windows and macOS only"
#endif

namespace sherpa_onnx {
inline std::string LoadedBufferSha256(const void* data, size_t size) {
  std::array<unsigned char, 32> digest{};
  const auto* next = static_cast<const unsigned char*>(data);
#if defined(_WIN32)
  struct Handles {
    BCRYPT_ALG_HANDLE algorithm = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    ~Handles() {
      if (hash) BCryptDestroyHash(hash);
      if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
    }
  } handles;
  auto check = [](NTSTATUS result) {
    if (result < 0) throw std::runtime_error("loaded model SHA-256 failed");
  };
  check(BCryptOpenAlgorithmProvider(&handles.algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0));
  check(BCryptCreateHash(handles.algorithm, &handles.hash, nullptr, 0, nullptr, 0, 0));
  while (size) {
    const auto count = static_cast<ULONG>(std::min<size_t>(size, (std::numeric_limits<ULONG>::max)()));
    check(BCryptHashData(handles.hash, const_cast<PUCHAR>(next), count, 0));
    next += count;
    size -= count;
  }
  check(BCryptFinishHash(handles.hash, digest.data(), digest.size(), 0));
#else
  CC_SHA256_CTX context;
  if (!CC_SHA256_Init(&context)) throw std::runtime_error("loaded model SHA-256 failed");
  while (size) {
    const auto count = static_cast<CC_LONG>(std::min<size_t>(size, std::numeric_limits<CC_LONG>::max()));
    if (!CC_SHA256_Update(&context, next, count)) throw std::runtime_error("loaded model SHA-256 failed");
    next += count;
    size -= count;
  }
  if (!CC_SHA256_Final(digest.data(), &context)) throw std::runtime_error("loaded model SHA-256 failed");
#endif
  const char* hex = "0123456789abcdef";
  std::string result = "sha256:";
  for (auto value : digest) {
    result += hex[value >> 4];
    result += hex[value & 15];
  }
  return result;
}

inline nlohmann::json LoadedSessionReadback(const Ort::Session& session) {
  Ort::AllocatorWithDefaultOptions allocator;
  char* data = nullptr;
  Ort::ThrowOnError(OrtGetSiglumeSessionReadback(session, allocator, &data));
  Ort::AllocatedStringPtr owned(data, Ort::detail::AllocatedFree(allocator));
  if (!owned) throw std::runtime_error("loaded session readback is missing");
  return nlohmann::json::parse(owned.get());
}
}  // namespace sherpa_onnx
#endif
