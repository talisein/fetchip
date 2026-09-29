#pragma once

#include <bit>
#include "dns.hpp"
#include <blobify/blobify.hpp>

constexpr auto properties(blob::tag<DNSHeader>) {
    blob::properties_t<DNSHeader> props {};

    props.expected_size = 12; // 16 * 6 / 8
    std::apply([](auto&... member){((member.endianness = std::endian::big), ...);}, props.members);

    return props;
}

constexpr auto properties(blob::tag<DNSQuestionBlob>) {
    blob::properties_t<DNSQuestionBlob> props {};


    props.member<&DNSQuestionBlob::qclass>().endianness    = std::endian::big;
    props.member<&DNSQuestionBlob::qclass>().validate_enum = true;

    props.member<&DNSQuestionBlob::qtype>().endianness     = std::endian::big;
    props.member<&DNSQuestionBlob::qtype>().validate_enum  = true;

    return props;
}

constexpr auto properties(blob::tag<DNSResourceRecordBlob>) {
    blob::properties_t<DNSResourceRecordBlob> props {};

    props.member<&DNSResourceRecordBlob::type>().endianness           = std::endian::big;
    props.member<&DNSResourceRecordBlob::type>().validate_enum        = false;
    props.member<&DNSResourceRecordBlob::query_class>().endianness    = std::endian::big;
    props.member<&DNSResourceRecordBlob::query_class>().validate_enum = false; // Could be UDP payload
    props.member<&DNSResourceRecordBlob::ttl>().endianness            = std::endian::big;
    props.member<&DNSResourceRecordBlob::rdlength>().endianness       = std::endian::big;
    return props;
}

constexpr auto properties(blob::tag<in_addr>) {
    blob::properties_t<in_addr> props {};

    props.member<&in_addr::s_addr>().endianness = std::endian::big;
    return props;
}

constexpr auto properties(blob::tag<DNSOptionBlob>) {
    blob::properties_t<DNSOptionBlob> props {};
    props.expected_size = 4;
    props.member<&DNSOptionBlob::option_code>().endianness    = std::endian::big;
    props.member<&DNSOptionBlob::option_code>().validate_enum = false;
    props.member<&DNSOptionBlob::data_size>().endianness      = std::endian::big;
    return props;
}

struct fetchip_construction_policy : blob::construction_policy {
    template<typename T, typename Representative, std::endian SourceEndianness>
    static T decode(Representative source) {
        if constexpr (std::is_enum_v<T>) {
            if constexpr (SourceEndianness != std::endian::native) {
                return static_cast<T>(std::byteswap(source));
            } else {
                return static_cast<T>(source);
            }
        } else {
            if constexpr (SourceEndianness != std::endian::native) {
                return T { std::byteswap(source) };
            } else {
                return T { source };
            }
        }
    }

    template<typename Representative, typename T, std::endian TargetEndianness>
    static Representative encode(const T& value) {
        if constexpr (std::is_enum_v<T>) {
            if constexpr (TargetEndianness != std::endian::native) {
                return std::byteswap(std::to_underlying(value));
            } else {
                return std::to_underlying(value);
            }
        } else {
            if constexpr (TargetEndianness != std::endian::native) {
                return std::byteswap(Representative { value });
            } else {
                return Representative { value };
            }
        }
    }
};

struct BlobLoader {
    BlobLoader(std::istream &is) : is(is) {}
    std::istream &is;

    void seek(std::ptrdiff_t num_bytes) {
        is.seekg(num_bytes, std::ios::cur);
        if (is.bad()) {
            throw std::system_error(make_error_code(DNSError::DeserializeStreamFailure), "seekg()");
        }
    }

    void load(std::byte* source, std::size_t num_bytes) {
        is.read(reinterpret_cast<char*>(source), num_bytes);
        if (is.fail()) {
            throw std::system_error(make_error_code(DNSError::DeserializeStreamFailure), "read()");
        }
    }
};

struct BlobStorer {
    BlobStorer(std::ostream &os) : os(os) { }
    std::ostream &os;

    void seek(std::ptrdiff_t num_bytes) {
        os.seekp(num_bytes, std::ios::cur);
        if (os.bad()) {
            throw std::system_error(make_error_code(DNSError::SerializeStreamFailure), "seek()");
        }
    }

    void store(std::byte* source, std::size_t num_bytes) {
        os.write(reinterpret_cast<char*>(source), num_bytes);
        if (os.fail()) {
            throw std::system_error(make_error_code(DNSError::SerializeStreamFailure), "write()");
        }
    }
};
