#include <net/capture/pcap_reader.h>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <fcntl.h>
    #include <sys/mman.h>
    #include <sys/stat.h>
    #include <unistd.h>
#endif

namespace net::pcap {

Reader::Reader(const std::filesystem::path& path) {
#ifdef _WIN32
    file_ = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file_ == INVALID_HANDLE_VALUE) {
        throw std::runtime_error("Reader: failed to open file");
    }

    LARGE_INTEGER size{};
    if (!GetFileSizeEx(file_, &size) || size.QuadPart == 0) {
        CloseHandle(file_);
        throw std::runtime_error("Reader: failed to get file size");
    }

    mapping_ = CreateFileMappingW(file_, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!mapping_) {
        CloseHandle(file_);
        throw std::runtime_error("Reader: failed to create file mapping");
    }

    span_ = std::span<const uint8_t>{static_cast<const uint8_t*>(MapViewOfFile(mapping_, FILE_MAP_READ, 0, 0, 0)),  static_cast<size_t>(size.QuadPart);};
    WIN32_MEMORY_RANGE_ENTRY r{(PVOID)span_, file_size_};
    PrefetchVirtualMemory(GetCurrentProcess(), 1, &r, 0);
    if (!span_.data()) {
        CloseHandle(mapping_);
        CloseHandle(file_);
        throw std::runtime_error("Reader: failed to map view");
    }
#else
    fd_ = ::open(path.c_str(), O_RDONLY);
    if (fd_ == -1) {
        throw std::runtime_error("Reader: failed to open file");
    }

    struct stat st{};
    if (::fstat(fd_, &st) == -1 || st.st_size == 0) {
        ::close(fd_);
        throw std::runtime_error("Reader: failed to get file size");
    }
    size_t size = static_cast<size_t>(st.st_size);

    void* m = ::mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd_, 0);
    ::madvise(const_cast<uint8_t*>(span_.data()), span_.size(), MADV_SEQUENTIAL);
    if (m == MAP_FAILED) {
        ::close(fd_);
        throw std::runtime_error("Reader: failed to mmap file");
    }
    span_ = std::span<const uint8_t>{static_cast<const uint8_t*>(m), size};
#endif
    readFileHeader();
}

Reader::~Reader() {
#ifdef _WIN32
    if (span_.data())  ::munmap(const_cast<uint8_t*>(span_.data()), span_.size());
    if (mapping_) CloseHandle(mapping_);
    if (file_ != INVALID_HANDLE_VALUE) CloseHandle(file_);
#else
    if (span_.data())  ::munmap(const_cast<uint8_t*>(span_.data()), span_.size());
    if (fd_ != -1) ::close(fd_);
#endif
}

void Reader::readAllPackets() {
    while (readPacket() == ParseError::None);
}

ParseError Reader::readPacket() {
    while (true) {
        if (span_.size() < PACKET_HEADER_LEN) {
            decoder_.finish();
            return ParseError::UnexpectedEofF;
        }

        if (auto err = parse(span_, capture_.packetHeader, endian_); err != ParseError::None) {
            return err;
        }

        if (span_.size() < capture_.packetHeader.incl_len) {
            return ParseError::UnexpectedEofF;
        }

        capture_.pkt.setDatatypeFromLinktype(file_header_.linktype);

        if (is_nsec_) {
            capture_.ts_us = static_cast<uint64_t>(capture_.packetHeader.ts_sec) * 1000000 + capture_.packetHeader.ts_usec / 1000;
        } else {
            capture_.ts_us = static_cast<uint64_t>(capture_.packetHeader.ts_sec) * 1000000 + capture_.packetHeader.ts_usec;
        }

        std::span<const uint8_t> packet_span{span_.data(), capture_.packetHeader.incl_len};
        span_ = span_.subspan(capture_.packetHeader.incl_len);

        if (auto err = decoder_.decode(packet_span, capture_); err != ParseError::None) {
            ++skipped_;
            last_skip_err_ = err;
            continue;
        }

        return ParseError::None;
    }
}

ParseError Reader::readFileHeader() {
    if (span_.size() < FILE_HEADER_LEN) {
        return ParseError::UnexpectedEofF;
    }
    if (auto err = parse(span_, file_header_, endian_); err != ParseError::None) return err;
    is_nsec_ = (file_header_.magic_number == PCAP_MAGIC_NSEC_LE || file_header_.magic_number == PCAP_MAGIC_NSEC_BE);
    return ParseError::None;
}

}