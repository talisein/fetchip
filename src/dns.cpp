#include <algorithm>
#include <expected>
#include <source_location>
#include <sstream>
#include <spanstream>
#include <ranges>
#include <iterator>
#include <iomanip>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <blobify/blobify.hpp>
#include <blobify/memory_storage.hpp>


#include "context.hpp"
#include "dns.hpp"

constexpr auto properties(blob::tag<DNSHeader>) {
    blob::properties_t<DNSHeader> props {};

    props.expected_size = 12; // 16 * 6 / 8
    std::apply([](auto&... member){((member.endianness = std::endian::big), ...);}, props.members);

    props.member_at<0>().endianness = std::endian::big;
    props.member_at<1>().endianness = std::endian::big;
    props.member_at<2>().endianness = std::endian::big;
    props.member_at<3>().endianness = std::endian::big;
    props.member_at<4>().endianness = std::endian::big;
    props.member_at<5>().endianness = std::endian::big;

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
    props.member<&DNSResourceRecordBlob::type>().validate_enum        = true;
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
    props.member<&DNSOptionBlob::option_code>().validate_enum = true;
    props.member<&DNSOptionBlob::data_size>().endianness      = std::endian::big;
    return props;
}

EDNS_ResourceRecord::EDNS_ResourceRecord(const DNSResourceRecordBlob& rr) :
    type(rr.type),
    payload_size(std::to_underlying(rr.query_class)),
    rdlength(rr.rdlength)
{
    union {
        uint32_t ttl;
        struct {
            uint8_t rcode;
            uint8_t version;
            uint16_t flags;
        } edns;
    } u;
    static_assert(sizeof(u) == sizeof(uint32_t));
    static_assert(sizeof(u.edns) == sizeof(u.ttl));
    u.ttl = rr.ttl;
    extendedRCode = u.edns.rcode;
    version = u.edns.version;
    flags = magic_enum::enum_value<DNSOptFlags>(u.edns.flags);
}

static std::error_code
dns_exception_handler(fip::context& ctx,
                      DNSError unexpected,
                      std::source_location src = std::source_location()) noexcept
{
    try {
        throw;
    } catch (blob::invalid_enum_value_exception_for<&DNSOptionBlob::option_code>& e) {
        ctx.log.debug("blobify invalid EDNSOptionCode {}", std::to_underlying(e.actual_value));
        return make_error_code(DNSError::DeserializeUnimplementedQueryType);
    } catch (blob::invalid_enum_value_exception_for<&EDNS_ResourceRecord::type>& e) {
        ctx.log.debug("blobify invalid DNSQueryType {}", std::to_underlying(e.actual_value));
        return make_error_code(DNSError::DeserializeUnimplementedQueryType);
    } catch (blob::invalid_enum_value_exception_for<&DNSResourceRecordBlob::query_class>& e) {
        ctx.log.debug("blobify invalid DNSQueryClass {}", std::to_underlying(e.actual_value));
        return make_error_code(DNSError::DeserializeUnimplementedQueryType);
    } catch (blob::invalid_enum_value_exception_for<&DNSResourceRecordBlob::type>& e) {
        ctx.log.debug("blobify invalid DNSQueryType {}", std::to_underlying(e.actual_value));
        return make_error_code(DNSError::DeserializeUnimplementedQueryType);
    } catch (blob::exception& e) {
        ctx.log.debug("blobify exception! {} typeid {}", src.function_name(), typeid(e).name());
        return DNSError::BlobifyStore;
    } catch (std::ios_base::failure& failure) {
        ctx.log.debug("std::ios_base::failure exception! {} value: {} what: {} message: {}",
                      src.function_name(), failure.code().value(), failure.what(), failure.code().message());
        return failure.code();
    } catch (std::system_error& e) {
        ctx.log.debug("system_error exception! {} value: {} what: {} message: {}",
                      src.function_name(), e.code().value(), e.what(), e.code().message());
        return e.code();
    } catch (std::exception& e) {
        ctx.log.debug("exception! {} what: {}",
                      src.function_name(), e.what());
        return make_error_code(unexpected);
    } catch (...) {
        ctx.log.debug("unexpected exception! {}", src.function_name());
        return make_error_code(unexpected);
    }
}


// Function to transform a regular host name to its DNS-encoded form
std::expected<void, std::error_code>
host_to_dnshost(fip::context& ctx, std::string_view host, std::ostream& os) noexcept {
    using namespace std::literals;
    try {
        for (const auto &subrange : std::views::split(host, "."sv)) {
            os.put(static_cast<uint8_t>(std::ranges::size(subrange)));
            std::ranges::copy(subrange, std::ostreambuf_iterator(os));
        }
        os.put('\0');

        if (!os.fail()) {
            return {};
        }
        return std::unexpected(make_error_code(DNSError::HostToDNSHostStreamFailure));
    } catch (...) {
        return std::unexpected(dns_exception_handler(ctx, DNSError::HostToDNSHostStreamUnexpectedException));
    }
}

namespace {
    std::error_code handle_eof(std::istream &is) {
        is.peek();
        if (is.eof()) {
            return make_error_code(DNSError::DNSHostToHostPrematureEOF);
        } else {
            return make_error_code(DNSError::DNSHostToHostStreamFailure);
        }
    };
}

std::expected<std::string, std::error_code>
dnshost_to_host(fip::context& ctx, std::istream& is, jump_table_t& jump_table) noexcept {
    std::ostringstream hostname;
    auto os_iter = std::ostreambuf_iterator(hostname);
    auto view = std::ranges::subrange(std::istreambuf_iterator(is), std::istreambuf_iterator<char>());
    const uint16_t start_pos = is.tellg();
    ctx.log.debug("Recorded start_pos {}", start_pos);
    try {
        do {
            uint8_t label_size = 0;
            if (auto copy_result = std::ranges::copy(std::views::take(view, 1), &label_size);
                copy_result.out == &label_size)
            {
                ctx.log.debug("No label after '{}'", hostname.view());
                return std::unexpected(handle_eof(is));
            }

            // If label size is zero, we're done.
            if (0 == label_size) {
                auto res = hostname.str();
                if (0 < res.size()) res.pop_back(); // Remove trailing .
                auto [it, _] = jump_table.emplace(start_pos, res);
                ctx.log.debug("Jump Table Insert: {}={}", it->first, it->second);
                return res;
            }
            const bool is_compressed = (label_size & 0xC0) == 0xC0;
            if (is_compressed) {
                uint8_t next;
                if (auto copy_result = std::ranges::copy(std::views::take(view, 1), &next);
                    copy_result.out == &next) {
                    ctx.log.debug("No compressed offset after '{}'", hostname.view());
                    return std::unexpected(handle_eof(is));
                }

                auto jump = static_cast<uint16_t>((label_size & 0x3F) << 8) | next;
                ctx.log.debug("Read compressed jump {}", jump);
                auto it = jump_table.find(jump);
                if (it != jump_table.end()) {
                    ctx.log.debug("Jump table answer: {}", it->second);
                    return it->second;
                }
            }

            if (64 < label_size) {
                ctx.log.debug("Got excessive label size {} after '{}'", label_size, hostname.view());
                return std::unexpected(make_error_code(DNSError::DNSHostToHostExcessiveHostLabelSize));
            }

            std::ranges::copy(std::views::take(view, label_size), os_iter);
            if (view.empty()) {
                ctx.log.debug("View is empty after '{}'", hostname.view());
                return std::unexpected(handle_eof(is));
            }
            *os_iter = '.';

        } while (hostname.tellp() < std::streamoff(257));
        ctx.log.debug("Excessive hostname size {} > 256: '{}'", static_cast<std::streamoff>(hostname.tellp()), hostname.view());
        return std::unexpected(make_error_code(DNSError::DNSHostToHostExcessiveHostnameSize));
    } catch (...) {
        return std::unexpected(dns_exception_handler(ctx, DNSError::DNSHostToHostStreamUnexpectedException));
    }
}


const detail::DNSError_category& DNSError_category()
{
  static detail::DNSError_category c;
  return c;
}

std::error_code make_error_code(DNSError e)
{
    return {magic_enum::enum_integer(e), DNSError_category()};
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

DNSMessage::DNSMessage(fip::context& ctx) noexcept :
    header(),
    ctx(ctx)
{
    std::uniform_int_distribution<decltype(header.id)> id_dist{ 0, std::numeric_limits<decltype(header.id)>::max() };
    header.id = id_dist(ctx.rng);
    header.flags = static_cast<DNSHeaderFlags>(RecursionDesired);

    /*
    RData_OPT opt {};
    opt.blob.payload_size = DNSBufferSize;
    opt.blob.version = 0;
    opt.blob.type = DNSQueryType::OPT;
    DNSOption cookie;
    cookie.blob.data_size = 8;
    cookie.blob.option_code = EDNSOptionCode::COOKIE;

    auto cookie_dist = std::uniform_int_distribution<uint8_t>{};
    std::generate_n(std::back_inserter(cookie.data), 8, [&]() -> uint8_t { return cookie_dist(ctx.rng); });
    opt.add_option(std::move(cookie));
    */
    // MEOW MEOW MEOW
    // make a DNSResourceRecord::set_edns(EDNS_OPT_Record) or something

//    additionals.push_back(std::move(opt));
}

std::expected<void, std::error_code>
RData_OPT::serialize(fip::context& ctx, std::ostream &os) const noexcept
{
    BlobStorer storage(os);
    try {
        for (const auto& option : options) {
            blob::store(storage, option.blob, blob::tag<fetchip_construction_policy>());
            std::ranges::copy(option.data, std::ostreambuf_iterator(os));
        }
    } catch (...) {
        return std::unexpected(dns_exception_handler(ctx, DNSError::SerializeUnexpectedException));
    }

    return {};
}

std::expected<RData_OPT, std::error_code>
RData_OPT::deserialize(fip::context& ctx, std::istream &is, size_t rdlen) noexcept
{
    BlobLoader loader(is);

    try {
        RData_OPT res {};
        const auto rdata_begin_pos = is.tellg();
        for (auto rdata_read = is.tellg() - rdata_begin_pos;
             std::cmp_less(rdata_read, rdlen);
             rdata_read = is.tellg() - rdata_begin_pos)
        {
            DNSOption option {};
            option.blob = blob::load<DNSOptionBlob>(loader, blob::tag<fetchip_construction_policy>());
            auto input_range = std::ranges::subrange(std::istreambuf_iterator(is), std::istreambuf_iterator<char>());
            std::ranges::copy(input_range | std::views::take(option.blob.data_size), std::back_inserter(option.data));
            if (option.blob.data_size < option.data.size()) {
                ctx.log.debug("Premature EOF deserializing option {}. {} < {}",
                              magic_enum::enum_name(option.blob.option_code),
                              option.blob.data_size,
                              option.data.size());
                return std::unexpected(make_error_code(DNSError::DeserializePrematureEOF));
            }
            res.options.push_back(std::move(option));
        }

        return res;
    } catch (...) {
        return std::unexpected(dns_exception_handler(ctx, DNSError::DeserializeUnexpectedException));
    }
}


std::expected<void, std::error_code>
DNSResourceRecord::serialize(fip::context& ctx, std::ostream& os) const noexcept
{
    BlobStorer storage(os);

    try {
        if (auto res = host_to_dnshost(ctx, name, os); !res) {
            // might as well reuse exception logging code since blob::store throws.
            throw std::system_error(res.error(), "host_to_dnshost()");
        }
        blob::store(storage, blob, blob::tag<fetchip_construction_policy>());

        RData_AAAA aaaa;
        RData_TXT txt;
        switch (blob.type) {
            case DNSQueryType::A:
                blob::store(storage, std::get<RData_A>(rdata), blob::tag<fetchip_construction_policy>());
                break;
            case DNSQueryType::AAAA:
                aaaa = std::get<RData_AAAA>(rdata);
                std::ranges::copy(std::span<uint8_t, 16>(aaaa.ipv6_address.s6_addr), std::ostreambuf_iterator(os));
                break;
            case DNSQueryType::TXT:
                txt = std::get<RData_TXT>(rdata);
                std::ranges::copy(txt.text, std::ostreambuf_iterator(os));
                break;
            default:
                ctx.log.info("Unimplemented! deserialized resource record type {}", magic_enum::enum_name(blob.type));
                break;
        }
    } catch (...) {
        return std::unexpected(dns_exception_handler(ctx, DNSError::SerializeUnexpectedException));
    }

    return {};
}

std::expected<DNSResourceRecord, std::error_code>
DNSResourceRecord::deserialize(fip::context& ctx, std::istream& is, jump_table_t& jump_table) noexcept
{
    BlobLoader loader(is);

    try {
        DNSResourceRecord res;

        if (auto hostname = dnshost_to_host(ctx, is, jump_table); !hostname) {
            throw std::system_error(hostname.error(), "DNSResourceRecord dnshost_to_host()");
        } else {
            res.name = *hostname;
        }
        ctx.log.debug("Got hostname '{}'", res.name);

        res.blob = blob::load<DNSResourceRecordBlob>(loader, blob::tag<fetchip_construction_policy>());

        ctx.log.debug("Got blob type '{}'", magic_enum::enum_name(res.blob.type));

        RData_AAAA aaaa;
        RData_TXT txt;
        uint8_t txt_len;
        std::expected<RData_OPT, std::error_code> opt;
        switch (res.blob.type) {
            case DNSQueryType::A:
                res.rdata = blob::load<RData_A>(loader, blob::tag<fetchip_construction_policy>());
                break;
            case DNSQueryType::AAAA:
                std::ranges::copy(std::ranges::subrange(std::istreambuf_iterator(is), std::istreambuf_iterator<char>()) | std::views::take(std::min<size_t>(res.blob.rdlength, sizeof(aaaa.ipv6_address.s6_addr))), aaaa.ipv6_address.s6_addr);
                res.rdata = aaaa;
                break;
            case DNSQueryType::TXT:
                txt_len = static_cast<uint8_t>(is.get());
                std::ranges::copy(std::ranges::subrange(std::istreambuf_iterator(is), std::istreambuf_iterator<char>()) | std::views::take(txt_len), std::back_inserter(txt.text));
                res.rdata = txt;
                break;
            case DNSQueryType::OPT:
                opt = RData_OPT::deserialize(ctx, is, res.blob.rdlength);
                if (opt) {
                    res.rdata = *opt;
                } else {
                    return std::unexpected(opt.error());
                }
                break;
            default:
                ctx.log.info("Unimplemented! deserialized resource record type {}", magic_enum::enum_name(res.blob.type));
                break;
        }

        return res;
    } catch (...) {
        return std::unexpected(dns_exception_handler(ctx, DNSError::DeserializeUnexpectedException));
    }
}

std::expected<void, std::error_code>
DNSQuestion::serialize(fip::context& ctx, std::ostream& os) const noexcept
{
    BlobStorer storage(os);

    try {
        if (auto res = host_to_dnshost(ctx, qname, os); !res) {
            // might as well reuse exception logging code since blob::store throws.
            throw std::system_error(res.error(), "host_to_dnshost()");
        }
        blob::store(storage, blob, blob::tag<fetchip_construction_policy>());
    } catch (...) {
        return std::unexpected(dns_exception_handler(ctx, DNSError::SerializeUnexpectedException));
    }

    return {};
}

std::expected<DNSQuestion, std::error_code>
DNSQuestion::deserialize(fip::context& ctx, std::istream& is, jump_table_t& jump_table) noexcept
{
    BlobLoader loader(is);

    try {
        DNSQuestion res;

        if (auto hostname = dnshost_to_host(ctx, is, jump_table); !hostname) {
            throw std::system_error(hostname.error(), "DNSQuestion dnshost_to_host()");
        } else {
            res.qname = *hostname;
        }

        res.blob = blob::load<DNSQuestionBlob>(loader, blob::tag<fetchip_construction_policy>());
        return res;
    } catch (...) {
        return std::unexpected(dns_exception_handler(ctx, DNSError::DeserializeUnexpectedException));
    }
}

std::expected<void, std::error_code>
DNSMessage::serialize(std::ostream& os) const noexcept
{
    BlobStorer storage(os);

    try {
        blob::store(storage, header, blob::tag<fetchip_construction_policy>());
        for (const auto& question : questions) {
            if (auto res = question.serialize(ctx, os); !res) {
                ctx.log.debug("Failed to serialize questions: {}", res.error().message());
                return std::unexpected(res.error());
            }
        }
        for (const auto& answer : answers) {
            if (auto res = answer.serialize(ctx, os); !res) {
                ctx.log.debug("Failed to serialize answers: {}", res.error().message());
                return std::unexpected(res.error());
            }
        }
        for (const auto& authority : authorities) {
            if (auto res = authority.serialize(ctx, os); !res) {
                ctx.log.debug("Failed to serialize authorities: {}", res.error().message());
                return std::unexpected(res.error());
            }
        }
        for (const auto& additional : additionals) {
            if (auto res = additional.serialize(ctx, os); !res) {
                ctx.log.debug("Failed to serialize additionals: {}", res.error().message());
                return std::unexpected(res.error());
            }
        }
    } catch (...) {
        return std::unexpected(dns_exception_handler(ctx, DNSError::SerializeUnexpectedException));
    }

    return {};
}

std::expected<DNSMessage, std::error_code>
DNSMessage::deserialize(fip::context& ctx, std::istream& is) noexcept
{
    BlobLoader loader(is);

    try {
        DNSMessage res(ctx);
        jump_table_t jump_table;

        res.header = blob::load<DNSHeader>(loader, blob::tag<fetchip_construction_policy>());
        ctx.log.debug("Got header {}", res.header);
        auto g = [&ctx, &is, &jump_table]<typename T> -> T {
            auto res = T::deserialize(ctx, is, jump_table);
            if (!res) throw std::system_error(res.error(), "try_deserialize");
            return *res;
        };
        auto g_q  = std::bind(&decltype(g)::operator()<DNSQuestion>, g);
        auto g_rr = std::bind(&decltype(g)::operator()<DNSResourceRecord>, g);

        std::ranges::generate_n(std::back_inserter(res.questions),   res.header.qdcount, g_q);
        for (const auto &q : res.questions) {
            ctx.log.debug("Got question {}", q);
        }
        std::ranges::generate_n(std::back_inserter(res.answers),     res.header.ancount, g_rr);
        for (const auto &q : res.answers) {
            ctx.log.debug("Got answer {}", q);
        }
        std::ranges::generate_n(std::back_inserter(res.authorities), res.header.nscount, g_rr);
        for (const auto &q : res.authorities) {
            ctx.log.debug("Got authority {}", q);
        }
        std::ranges::generate_n(std::back_inserter(res.additionals), res.header.arcount, g_rr);
        for (const auto &q : res.additionals) {
            ctx.log.debug("Got additional {}", q);
        }

        return res;
    } catch (...) {
        return std::unexpected(dns_exception_handler(ctx, DNSError::DeserializeUnexpectedException));
    }
}
