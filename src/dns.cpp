#include <algorithm>
#include <expected>
#include <source_location>
#include <ranges>
#include <iterator>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <blobify/blobify.hpp>

#include "context.hpp"
#include "dns.hpp"

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


namespace {
    // Function to transform a regular host name to its DNS-encoded form
    std::expected<void, std::error_code>
    host_to_dnshost(fip::context& ctx, std::string_view host, std::ostream& os) {
        using namespace std::literals;

        for (const auto &subrange : std::views::split(host, "."sv)) {
            os.put(static_cast<uint8_t>(std::ranges::size(subrange)));
            std::ranges::copy(subrange, std::ostreambuf_iterator(os));
        }
        os.put('\0');

        if (!os.fail()) {
            return {};
        }
        return std::unexpected(make_error_code(DNSError::HostToDNSHostStreamFailure));
    }

    std::error_code handle_eof(std::istream &is) {
        is.peek();
        if (is.eof()) {
            return make_error_code(DNSError::DNSHostToHostPrematureEOF);
        } else {
            return make_error_code(DNSError::DNSHostToHostStreamFailure);
        }
    }

    consteval std::streamoff
    operator""_soff(unsigned long long x)
    {
        return static_cast<std::streamoff>(x);
    }

    std::expected<std::string, std::error_code>
    dnshost_to_host(fip::context& ctx, std::istream& is, jump_table_t& jump_table) {
        std::ostringstream hostname;
        auto os_iter = std::ostreambuf_iterator(hostname);
        auto view = std::ranges::subrange(std::istreambuf_iterator(is), std::istreambuf_iterator<char>());
        const uint16_t start_pos = is.tellg();

        do {
            uint8_t label_size = 0;
            if (auto copy_result = std::ranges::copy(std::views::take(view, 1), &label_size);
                copy_result.out == &label_size)
            {
                return std::unexpected(handle_eof(is));
            }

            // If label size is zero, we're done.
            if (0 == label_size) {
                auto res = hostname.str();
                if (0 < res.size()) res.pop_back(); // Remove trailing .
                auto [it, _] = jump_table.emplace(start_pos, std::move(res));
                return it->second;
            }

            const bool is_compressed = (label_size & 0xC0) == 0xC0;
            if (is_compressed) {
                uint8_t next;
                if (auto copy_result = std::ranges::copy(std::views::take(view, 1), &next);
                    copy_result.out == &next) {
                    return std::unexpected(handle_eof(is));
                }

                auto jump = static_cast<uint16_t>((label_size & 0x3F) << 8) | next;
                auto it = jump_table.find(jump);
                if (it != jump_table.end()) {
                    return it->second;
                }
            }

            if (64 < label_size) {
                return std::unexpected(make_error_code(DNSError::DNSHostToHostExcessiveHostLabelSize));
            }

            std::ranges::copy(std::views::take(view, label_size), os_iter);
            if (view.empty()) {
                return std::unexpected(handle_eof(is));
            }
            *os_iter = '.';

        } while (hostname.tellp() < 257_soff);
        ctx.log.debug("Excessive hostname size {} > 256: '{}'", static_cast<std::streamoff>(hostname.tellp()), hostname.view());
        return std::unexpected(make_error_code(DNSError::DNSHostToHostExcessiveHostnameSize));
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

DNSMessage::DNSMessage(fip::context& ctx) noexcept :
    header(),
    ctx(ctx)
{
    std::uniform_int_distribution<decltype(header.id)> id_dist{ 0, std::numeric_limits<decltype(header.id)>::max() };
    header.id = id_dist(ctx.rng);
    header.flags = static_cast<DNSHeaderFlags>(RecursionDesired);
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
                for (const auto& text : txt.strings) {
                    if (text.size() > std::numeric_limits<uint8_t>::max()) {
                        ctx.log.debug("TXT string too long to serialize: {} bytes", text.size());
                        return std::unexpected(make_error_code(DNSError::SerializeStreamFailure));
                    }
                    os.put(static_cast<char>(text.size()));
                    std::ranges::copy(text, std::ostreambuf_iterator(os));
                }
                break;
            default:
                ctx.log.debug("Unimplemented! deserialized resource record type {}", magic_enum::enum_name(blob.type));
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

        RData_AAAA aaaa {};
        RData_TXT txt;
        std::string txt_rdata;
        std::expected<RData_OPT, std::error_code> opt;
        switch (res.blob.type) {
            case DNSQueryType::A:
                if (res.blob.rdlength != sizeof(in_addr)) {
                    ctx.log.debug("A record with rdlength {}", res.blob.rdlength);
                    return std::unexpected(make_error_code(DNSError::DeserializePrematureEOF));
                }
                res.rdata = blob::load<RData_A>(loader, blob::tag<fetchip_construction_policy>());
                break;
            case DNSQueryType::AAAA:
                if (res.blob.rdlength != sizeof(aaaa.ipv6_address.s6_addr)) {
                    ctx.log.debug("AAAA record with rdlength {}", res.blob.rdlength);
                    return std::unexpected(make_error_code(DNSError::DeserializePrematureEOF));
                }
                if (auto copied = std::ranges::copy(std::ranges::subrange(std::istreambuf_iterator(is), std::istreambuf_iterator<char>()) | std::views::take(sizeof(aaaa.ipv6_address.s6_addr)), aaaa.ipv6_address.s6_addr);
                    copied.out != std::end(aaaa.ipv6_address.s6_addr)) {
                    ctx.log.debug("Premature EOF deserializing AAAA record");
                    return std::unexpected(make_error_code(DNSError::DeserializePrematureEOF));
                }
                res.rdata = aaaa;
                break;
            case DNSQueryType::TXT:
                if (res.blob.rdlength == 0) {
                    ctx.log.debug("TXT record with rdlength 0");
                    return std::unexpected(make_error_code(DNSError::DeserializePrematureEOF));
                }
                std::ranges::copy(std::ranges::subrange(std::istreambuf_iterator(is), std::istreambuf_iterator<char>()) | std::views::take(res.blob.rdlength), std::back_inserter(txt_rdata));
                if (txt_rdata.size() != res.blob.rdlength) {
                    ctx.log.debug("Premature EOF deserializing TXT record. {} < {}", txt_rdata.size(), res.blob.rdlength);
                    return std::unexpected(make_error_code(DNSError::DeserializePrematureEOF));
                }
                // The rdata is a run of character-strings, each a length byte and that many bytes.
                for (std::string_view rest {txt_rdata}; !rest.empty(); ) {
                    const auto txt_len = static_cast<uint8_t>(rest.front());
                    rest.remove_prefix(1);
                    if (txt_len > rest.size()) {
                        ctx.log.debug("TXT string length {} overruns the {} bytes left", txt_len, rest.size());
                        return std::unexpected(make_error_code(DNSError::DeserializePrematureEOF));
                    }
                    txt.strings.emplace_back(rest.substr(0, txt_len));
                    rest.remove_prefix(txt_len);
                }
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
                // Skipped whole, so a CNAME ahead of the answer leaves the records after it readable.
                ctx.log.debug("Skipping {} bytes of unimplemented resource record type {}", res.blob.rdlength, magic_enum::enum_name(res.blob.type));
                if (is.ignore(res.blob.rdlength).gcount() != res.blob.rdlength) {
                    ctx.log.debug("Premature EOF skipping {} record", magic_enum::enum_name(res.blob.type));
                    return std::unexpected(make_error_code(DNSError::DeserializePrematureEOF));
                }
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

namespace {
    // Generator for std::ranges::generate_n: deserializes one T or throws.
    template <typename T>
    struct throwing_deserializer {
        fip::context& ctx;
        std::istream& is;
        jump_table_t& jump_table;

        T operator()() const {
            auto res = T::deserialize(ctx, is, jump_table);
            if (!res) throw std::system_error(res.error(), "try_deserialize");
            return *res;
        }
    };
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
        throwing_deserializer<DNSQuestion>       g_q {ctx, is, jump_table};
        throwing_deserializer<DNSResourceRecord> g_rr{ctx, is, jump_table};

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
