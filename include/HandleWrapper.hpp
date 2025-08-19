#pragma once

#include "utils.hpp"

namespace EDRSilencer {

class Handle {
public:
    Handle() noexcept : h_(nullptr) {}
    explicit Handle(HANDLE h) noexcept : h_(h) {}
    ~Handle() { close(); }

    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;

    Handle(Handle&& other) noexcept : h_(other.h_) { other.h_ = nullptr; }
    Handle& operator=(Handle&& other) noexcept {
        if (this != &other) {
            close();
            h_ = other.h_;
            other.h_ = nullptr;
        }
        return *this;
    }

    void reset(HANDLE h = nullptr) noexcept {
        close();
        h_ = h;
    }

    bool valid() const noexcept { return h_ && h_ != INVALID_HANDLE_VALUE; }
    HANDLE get() const noexcept { return h_; }
    HANDLE release() noexcept { HANDLE t = h_; h_ = nullptr; return t; }

private:
    void close() noexcept {
        if (h_ && h_ != INVALID_HANDLE_VALUE) {
            CloseHandle(h_);
            h_ = nullptr;
        }
    }

    HANDLE h_;
};

} // namespace EDRSilencer
