#pragma once

#include <unknwn.h>
#include <utility>

namespace EDRSilencer {

// Minimal COM smart pointer for automatic Release().
// Copy disabled; movable.

template <typename T>
class ComPtr {
public:
    ComPtr() noexcept : ptr_(nullptr) {}
    explicit ComPtr(T* p) noexcept : ptr_(p) {}
    ~ComPtr() { reset(); }

    ComPtr(const ComPtr&) = delete;
    ComPtr& operator=(const ComPtr&) = delete;

    ComPtr(ComPtr&& other) noexcept : ptr_(other.ptr_) { other.ptr_ = nullptr; }
    ComPtr& operator=(ComPtr&& other) noexcept {
        if (this != &other) {
            reset();
            ptr_ = other.ptr_;
            other.ptr_ = nullptr;
        }
        return *this;
    }

    void reset(T* p = nullptr) noexcept {
        if (ptr_) {
            ptr_->Release();
        }
        ptr_ = p;
    }

    T* get() const noexcept { return ptr_; }
    T** put() noexcept { reset(); return &ptr_; }
    void** put_void() noexcept { reset(); return reinterpret_cast<void**>(&ptr_); }
    T* const* address_of() const noexcept { return &ptr_; }
    T** address_of() noexcept { return &ptr_; }

    T* detach() noexcept { T* tmp = ptr_; ptr_ = nullptr; return tmp; }
    void attach(T* p) noexcept { reset(); ptr_ = p; }

    T& operator*() const noexcept { return *ptr_; }
    T* operator->() const noexcept { return ptr_; }
    explicit operator bool() const noexcept { return ptr_ != nullptr; }

private:
    T* ptr_;
};

} // namespace EDRSilencer
