#include <algorithm>
#include <expected>
#include <optional>
#include <source_location>
#include <ranges>
#include <iterator>
#include <spanstream>

#include <unistd.h>

#include <blobify/blobify.hpp>

#include "context.hpp"
#include "dns.hpp"

EDNS_ResourceRecord::EDNS_ResourceRecord(const DNSResourceRecordBlob& rr) :
    type(rr.type),
    payload_size(std::to_underlying(rr.query_class)),
    // rr.ttl is already in host order: EXTENDED-RCODE | VERSION | flags
    extendedRCode(static_cast<uint8_t>(rr.ttl >> opt_ttl_extended_rcode_shift)),
    version(static_cast<uint8_t>(rr.ttl >> opt_ttl_version_shift)),
    flags(static_cast<DNSOptFlags>(rr.ttl & std::numeric_limits<uint16_t>::max())),
    rdlength(rr.rdlength)
{
}

static std::error_code
dns_exception_handler(fip::context& ctx,
                      DNSError unexpected,
                      std::source_location src = std::source_location::current()) noexcept
{
    try {
        throw;
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
    // An ostreambuf_iterator records a short write only in itself, never in the stream.
    [[nodiscard]] std::expected<void, std::error_code>
    store_bytes(std::ranges::input_range auto&& bytes, std::ostream& os) {
        if (std::ranges::copy(bytes, std::ostreambuf_iterator(os)).out.failed() || os.fail()) {
            return std::unexpected(make_error_code(DNSError::SerializeStreamFailure));
        }
        return {};
    }

    [[nodiscard]] std::expected<void, std::error_code>
    load_bytes(std::ranges::sized_range auto& bytes, std::istream& is) {
        auto stream = std::ranges::subrange(std::istreambuf_iterator(is), std::istreambuf_iterator<char>())
                    | std::views::take(std::ranges::size(bytes));
        const auto copied = std::ranges::copy(stream, std::ranges::begin(bytes));
        if (copied.out != std::ranges::end(bytes)) {
            return std::unexpected(make_error_code(DNSError::DeserializePrematureEOF));
        }
        return {};
    }

    // Function to transform a regular host name to its DNS-encoded form
    std::expected<void, std::error_code>
    host_to_dnshost(fip::context& ctx, std::string_view host, std::ostream& os) {
        using namespace std::literals;

        if (auto valid = validate_dns_name(host); !valid) {
            ctx.log.debug("Invalid DNS name '{}' of size {}: {}", host, host.size(), valid.error().message());
            return std::unexpected(valid.error());
        }
        for (const auto &label : std::views::split(host, "."sv)) {
            if (auto res = store_bytes(std::views::single(static_cast<char>(std::ranges::size(label))), os); !res) {
                return std::unexpected(res.error());
            }
            if (auto res = store_bytes(label, os); !res) {
                return std::unexpected(res.error());
            }
        }
        return store_bytes(std::views::single('\0'), os);
    }

    std::error_code handle_eof(std::istream &is) {
        is.peek();
        if (is.eof()) {
            return make_error_code(DNSError::DNSHostToHostPrematureEOF);
        } else {
            return make_error_code(DNSError::DNSHostToHostStreamFailure);
        }
    }

    // The stream's position as a compression pointer names it; tellg() answers -1 once the stream has failed.
    std::expected<uint16_t, std::error_code> wire_offset(std::istream& is) {
        const std::streamoff pos = is.tellg();
        if (pos < 0) {
            return std::unexpected(handle_eof(is));
        }
        if (std::numeric_limits<uint16_t>::max() < pos) {
            return std::unexpected(make_error_code(DNSError::DNSHostToHostStreamFailure));
        }
        return static_cast<uint16_t>(pos);
    }

    std::expected<std::string, std::error_code>
    dnshost_to_host(fip::context& ctx, std::istream& is, jump_table_t& jump_table) {
        std::ostringstream hostname;
        auto os_iter = std::ostreambuf_iterator(hostname);
        auto view = std::ranges::subrange(std::istreambuf_iterator(is), std::istreambuf_iterator<char>());
        const auto start_pos = wire_offset(is);
        if (!start_pos) {
            return std::unexpected(start_pos.error());
        }
        // Where the caller's parse continues: just past the first compression
        // pointer, since a pointer ends the name on the wire.
        std::optional<uint16_t> resume;

        do {
            const auto label_pos = wire_offset(is);
            if (!label_pos) {
                return std::unexpected(label_pos.error());
            }
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
                if (resume) is.seekg(*resume);
                auto [it, _] = jump_table.emplace(*start_pos, std::move(res));
                return it->second;
            }

            const bool is_compressed = (label_size & compression_pointer_flag) == compression_pointer_flag;
            if (is_compressed) {
                uint8_t next;
                if (auto copy_result = std::ranges::copy(std::views::take(view, 1), &next);
                    copy_result.out == &next) {
                    return std::unexpected(handle_eof(is));
                }

                auto jump = static_cast<uint16_t>((label_size & compression_offset_high_mask) << compression_offset_high_shift) | next;
                if (auto it = jump_table.find(jump); it != jump_table.end()) {
                    // The accumulated prefix ends in '.'; the cached name has none.
                    auto res = hostname.str() + it->second;
                    if (0 < res.size() && '.' == res.back()) res.pop_back(); // Pointer to the root name
                    if (max_name_text < res.size()) {
                        ctx.log.debug("Excessive hostname size {} > {}: '{}'", res.size(), max_name_text, res);
                        return std::unexpected(make_error_code(DNSError::DNSHostToHostExcessiveHostnameSize));
                    }

                    if (resume) is.seekg(*resume);
                    auto [res_it, _] = jump_table.emplace(*start_pos, std::move(res));
                    return res_it->second;
                }

                // A pointer may only reference a prior occurrence, so each jump
                // moves strictly backward and a chain of them must terminate.
                if (jump >= *label_pos) {
                    ctx.log.debug("Compression pointer at {} jumps forward to {}", *label_pos, jump);
                    return std::unexpected(make_error_code(DNSError::DNSHostToHostBadCompressionPointer));
                }
                if (!resume) {
                    const auto after_pointer = wire_offset(is);
                    if (!after_pointer) {
                        return std::unexpected(after_pointer.error());
                    }
                    resume = *after_pointer;
                }
                is.seekg(jump);
                view = std::ranges::subrange(std::istreambuf_iterator(is), std::istreambuf_iterator<char>());
                continue;
            }

            if (max_label_octets < label_size) {
                return std::unexpected(make_error_code(DNSError::DNSHostToHostExcessiveHostLabelSize));
            }

            std::ranges::copy(std::views::take(view, label_size), os_iter);
            if (view.empty()) {
                return std::unexpected(handle_eof(is));
            }
            *os_iter = '.';

            // Each label is followed by '.', so the stream is one shy of the
            // wire length: the terminating zero octet must still fit.
        } while (hostname.view().size() < max_name_octets);
        ctx.log.debug("Excessive hostname size {} > {}: '{}'", hostname.view().size() + 1, max_name_octets, hostname.view());
        return std::unexpected(make_error_code(DNSError::DNSHostToHostExcessiveHostnameSize));
    }
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
            if (auto res = store_bytes(option.data, os); !res) {
                return std::unexpected(res.error());
            }
        }
    } catch (...) {
        return std::unexpected(dns_exception_handler(ctx, DNSError::SerializeUnexpectedException));
    }

    return {};
}

std::expected<RData_OPT, std::error_code>
RData_OPT::deserialize(fip::context& ctx, std::istream &is, size_t rdlen) noexcept
{
    try {
        // Options are parsed from the rdata alone, so no option can reach the records after it.
        std::vector<char> rdata;
        std::ranges::copy(std::ranges::subrange(std::istreambuf_iterator(is), std::istreambuf_iterator<char>()) | std::views::take(rdlen), std::back_inserter(rdata));
        if (rdata.size() != rdlen) {
            ctx.log.debug("Premature EOF deserializing OPT record. {} < {}", rdata.size(), rdlen);
            return std::unexpected(make_error_code(DNSError::DeserializePrematureEOF));
        }

        std::ispanstream rdata_stream {rdata};
        BlobLoader loader(rdata_stream);
        RData_OPT res {};
        auto rdata_left = rdata.size();
        while (rdata_left > 0) {
            if (rdata_left < option_header_octets) {
                ctx.log.debug("Option header overruns the {} bytes of rdata left", rdata_left);
                return std::unexpected(make_error_code(DNSError::DeserializePrematureEOF));
            }
            DNSOption option {};
            option.blob = blob::load<DNSOptionBlob>(loader, blob::tag<fetchip_construction_policy>());
            auto input_range = std::ranges::subrange(std::istreambuf_iterator(rdata_stream), std::istreambuf_iterator<char>());
            std::ranges::copy(input_range | std::views::take(option.blob.data_size), std::back_inserter(option.data));
            if (option.data.size() < option.blob.data_size) {
                ctx.log.debug("Option {} data size {} overruns the {} bytes of rdata left",
                              enum_name_or_value(option.blob.option_code),
                              option.blob.data_size,
                              option.data.size());
                return std::unexpected(make_error_code(DNSError::DeserializePrematureEOF));
            }
            rdata_left -= option_header_octets + option.data.size();
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
        // Each case takes and checks its rdata before calling store_header, so a record that cannot be serialized writes nothing.
        const auto store_header = [&]() -> std::expected<void, std::error_code> {
            if (auto res = host_to_dnshost(ctx, name, os); !res) {
                return std::unexpected(res.error());
            }
            blob::store(storage, blob, blob::tag<fetchip_construction_policy>());
            return {};
        };

        switch (blob.type) {
            case DNSQueryType::A: {
                const auto& a = std::get<RData_A>(rdata);
                if (auto res = store_header(); !res) {
                    return std::unexpected(res.error());
                }
                return store_bytes(a.ipv4_address, os);
            }
            case DNSQueryType::AAAA: {
                const auto& aaaa = std::get<RData_AAAA>(rdata);
                if (auto res = store_header(); !res) {
                    return std::unexpected(res.error());
                }
                return store_bytes(aaaa.ipv6_address, os);
            }
            case DNSQueryType::TXT: {
                const auto& txt = std::get<RData_TXT>(rdata);
                if (auto oversized = std::ranges::find_if(txt.strings, [](const auto& s) { return max_character_string_octets < s.size(); });
                    oversized != txt.strings.end()) {
                    ctx.log.debug("TXT string too long to serialize: {} > {} bytes", oversized->size(), max_character_string_octets);
                    return std::unexpected(make_error_code(DNSError::SerializeExcessiveTextSize));
                }
                if (auto res = store_header(); !res) {
                    return std::unexpected(res.error());
                }
                for (const auto& text : txt.strings) {
                    if (auto res = store_bytes(std::views::single(static_cast<char>(text.size())), os); !res) {
                        return std::unexpected(res.error());
                    }
                    if (auto res = store_bytes(text, os); !res) {
                        return std::unexpected(res.error());
                    }
                }
                return {};
            }
            case DNSQueryType::OPT: {
                const auto& opt = std::get<RData_OPT>(rdata);
                if (auto res = store_header(); !res) {
                    return std::unexpected(res.error());
                }
                return opt.serialize(ctx, os);
            }
            default:
                ctx.log.debug("Unimplemented! Cannot serialize resource record type {}", enum_name_or_value(blob.type));
                return std::unexpected(make_error_code(DNSError::SerializeUnimplementedType));
        }
    } catch (...) {
        return std::unexpected(dns_exception_handler(ctx, DNSError::SerializeUnexpectedException));
    }
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

        ctx.log.debug("Got blob type '{}'", enum_name_or_value(res.blob.type));

        RData_A a {};
        RData_AAAA aaaa {};
        RData_TXT txt {};
        std::string txt_rdata;
        std::expected<RData_OPT, std::error_code> opt;
        switch (res.blob.type) {
            case DNSQueryType::A:
                if (res.blob.rdlength != a.ipv4_address.size()) {
                    ctx.log.debug("A record with rdlength {}", res.blob.rdlength);
                    return std::unexpected(make_error_code(DNSError::DeserializePrematureEOF));
                }
                if (auto loaded = load_bytes(a.ipv4_address, is); !loaded) {
                    ctx.log.debug("Premature EOF deserializing A record");
                    return std::unexpected(loaded.error());
                }
                res.rdata = a;
                break;
            case DNSQueryType::AAAA:
                if (res.blob.rdlength != aaaa.ipv6_address.size()) {
                    ctx.log.debug("AAAA record with rdlength {}", res.blob.rdlength);
                    return std::unexpected(make_error_code(DNSError::DeserializePrematureEOF));
                }
                if (auto loaded = load_bytes(aaaa.ipv6_address, is); !loaded) {
                    ctx.log.debug("Premature EOF deserializing AAAA record");
                    return std::unexpected(loaded.error());
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
                ctx.log.debug("Skipping {} bytes of unimplemented resource record type {}", res.blob.rdlength, enum_name_or_value(res.blob.type));
                if (is.ignore(res.blob.rdlength).gcount() != res.blob.rdlength) {
                    ctx.log.debug("Premature EOF skipping {} record", enum_name_or_value(res.blob.type));
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
            return std::unexpected(res.error());
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
