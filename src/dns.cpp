#include <algorithm>
#include <expected>
#include <format>
#include <functional>
#include <optional>
#include <source_location>
#include <ranges>
#include <iterator>
#include <spanstream>
#include <system_error>

#include <blobify/blobify.hpp>
#include <boost/pfr/core.hpp>

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

    // The rdata is a run of character-strings, each a length byte and that many bytes.
    [[nodiscard]] std::expected<std::vector<std::string>, std::error_code>
    parse_character_strings(fip::context& ctx, std::string_view rdata) {
        std::vector<std::string> strings;
        for (std::string_view rest {rdata}; !rest.empty(); ) {
            const auto txt_len = static_cast<uint8_t>(rest.front());
            rest.remove_prefix(1);
            if (txt_len > rest.size()) {
                ctx.log.debug("TXT string length {} overruns the {} bytes left", txt_len, rest.size());
                return std::unexpected(make_error_code(DNSError::DeserializePrematureEOF));
            }
            strings.emplace_back(rest.substr(0, txt_len));
            rest.remove_prefix(txt_len);
        }
        return strings;
    }

    // Names the enum value blobify's validation refused loading a T, from the exception in flight.
    template <typename T, size_t member = 0>
    [[nodiscard]] std::string
    invalid_value_text() {
        if constexpr (member == boost::pfr::tuple_size_v<T>) {
            return "value";
        } else {
            using member_type = boost::pfr::tuple_element_t<member, T>;
            if constexpr (std::is_enum_v<member_type>) {
                try {
                    throw;
                } catch (const blob::invalid_enum_value_exception<member_type>& e) {
                    const auto value = enum_name_or_value(e.actual_value);
                    return std::format("{} {}", magic_enum::enum_type_name<member_type>(), value);
                } catch (const blob::exception&) {
                    // Not this member's enum; a later member may name it.
                }
            }
            return invalid_value_text<T, member + 1>();
        }
    }

    // Converts what blobify throws loading a T (a short read, a refused value) into an error code.
    template <typename T>
    [[nodiscard]] std::expected<T, std::error_code>
    load_blob(fip::context& ctx,
              BlobLoader& loader,
              std::source_location src = std::source_location::current()) {
        try {
            return blob::load<T>(loader, blob::tag<fetchip_construction_policy>());
        } catch (const std::system_error& e) {
            ctx.log.debug("system_error exception! {} value: {} what: {} message: {}",
                          src.function_name(), e.code().value(), e.what(), e.code().message());
            return std::unexpected(e.code());
        } catch (const blob::exception&) {
            // blobify's storage_exhausted_exception comes only from its own storage backends, never
            // BlobLoader, so what reaches here is a field its validation refused.
            ctx.log.debug("{}: invalid {}", src.function_name(), invalid_value_text<T>());
            return std::unexpected(make_error_code(DNSError::DeserializeInvalidValue));
        }
    }

    // Converts what blobify throws storing a value (a short write) into an error code.
    [[nodiscard]] std::expected<void, std::error_code>
    store_blob(fip::context& ctx,
               BlobStorer& storage,
               const auto& value,
               std::source_location src = std::source_location::current()) {
        try {
            blob::store(storage, value, blob::tag<fetchip_construction_policy>());
        } catch (const std::system_error& e) {
            ctx.log.debug("system_error exception! {} value: {} what: {} message: {}",
                          src.function_name(), e.code().value(), e.what(), e.code().message());
            return std::unexpected(e.code());
        }
        return {};
    }

    [[nodiscard]] std::expected<uint16_t, std::error_code>
    rdlength_of(fip::context& ctx, size_t octets) {
        if (max_rdata_octets < octets) {
            ctx.log.debug("Rdata too long to serialize: {} > {} bytes", octets, max_rdata_octets);
            return std::unexpected(make_error_code(DNSError::SerializeExcessiveRdataSize));
        }
        return static_cast<uint16_t>(octets);
    }

    [[nodiscard]] size_t
    rdata_octets(const RData_TXT& txt) {
        const auto octets_of = [](const auto& text) { return sizeof(uint8_t) + text.size(); };
        return std::ranges::fold_left(txt.strings | std::views::transform(octets_of), size_t {0}, std::plus {});
    }

    [[nodiscard]] size_t
    rdata_octets(const RData_OPT& opt) {
        const auto octets_of = [](const auto& option) { return option_header_octets + option.data.size(); };
        return std::ranges::fold_left(opt.options | std::views::transform(octets_of), size_t {0}, std::plus {});
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

    struct WireName {
        std::string prefix;
        std::string suffix;
        // Where the caller's parse continues: just past the first compression
        // pointer, since a pointer ends the name on the wire.
        std::optional<uint16_t> resume;
    };

    std::expected<WireName, std::error_code>
    walk_name(fip::context& ctx, std::istream& is, const jump_table_t& jump_table) {
        std::ostringstream hostname;
        auto os_iter = std::ostreambuf_iterator(hostname);
        auto view = std::ranges::subrange(std::istreambuf_iterator(is), std::istreambuf_iterator<char>());
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
                return WireName{hostname.str(), {}, resume};
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
                    return WireName{hostname.str(), it->second, resume};
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

    std::expected<std::string, std::error_code>
    dnshost_to_host(fip::context& ctx, std::istream& is, jump_table_t& jump_table) {
        const auto start_pos = wire_offset(is);
        if (!start_pos) {
            return std::unexpected(start_pos.error());
        }
        auto wire = walk_name(ctx, is, jump_table);
        if (!wire) {
            return std::unexpected(wire.error());
        }

        // The prefix ends in '.' and a cached suffix has none, unless the suffix is the root.
        auto name = std::move(wire->prefix) + wire->suffix;
        if (0 < name.size() && '.' == name.back()) name.pop_back();
        if (max_name_text < name.size()) {
            ctx.log.debug("Excessive hostname size {} > {}: '{}'", name.size(), max_name_text, name);
            return std::unexpected(make_error_code(DNSError::DNSHostToHostExcessiveHostnameSize));
        }

        if (wire->resume) is.seekg(*wire->resume);
        auto [it, _] = jump_table.emplace(*start_pos, std::move(name));
        return it->second;
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
RData_OPT::serialize(fip::context& ctx, std::ostream &os) const
{
    BlobStorer storage(os);
    // Checked whole before the first option is written. Each OPTION-LENGTH counts part of the
    // rdata, so rdata that fits RDLENGTH leaves no option too long for its own.
    const auto rdlength = rdlength_of(ctx, rdata_octets(*this));
    if (!rdlength) {
        return std::unexpected(rdlength.error());
    }
    for (const auto& option : options) {
        // OPTION-LENGTH is the size of the data written after it, never the stored blob.data_size.
        auto header = option.blob;
        header.data_size = static_cast<uint16_t>(option.data.size());
        if (auto res = store_blob(ctx, storage, header); !res) {
            return std::unexpected(res.error());
        }
        if (auto res = store_bytes(option.data, os); !res) {
            return std::unexpected(res.error());
        }
    }

    return {};
}

std::expected<RData_A, std::error_code>
RData_A::deserialize(fip::context& ctx, std::istream &is, size_t rdlen)
{
    RData_A res {};
    if (rdlen != res.ipv4_address.size()) {
        ctx.log.debug("A record with rdlength {}", rdlen);
        return std::unexpected(make_error_code(DNSError::DeserializePrematureEOF));
    }
    if (auto loaded = load_bytes(res.ipv4_address, is); !loaded) {
        ctx.log.debug("Premature EOF deserializing A record");
        return std::unexpected(loaded.error());
    }
    return res;
}

std::expected<RData_AAAA, std::error_code>
RData_AAAA::deserialize(fip::context& ctx, std::istream &is, size_t rdlen)
{
    RData_AAAA res {};
    if (rdlen != res.ipv6_address.size()) {
        ctx.log.debug("AAAA record with rdlength {}", rdlen);
        return std::unexpected(make_error_code(DNSError::DeserializePrematureEOF));
    }
    if (auto loaded = load_bytes(res.ipv6_address, is); !loaded) {
        ctx.log.debug("Premature EOF deserializing AAAA record");
        return std::unexpected(loaded.error());
    }
    return res;
}

std::expected<RData_TXT, std::error_code>
RData_TXT::deserialize(fip::context& ctx, std::istream &is, size_t rdlen)
{
    if (rdlen == 0) {
        ctx.log.debug("TXT record with rdlength 0");
        return std::unexpected(make_error_code(DNSError::DeserializePrematureEOF));
    }
    std::string rdata;
    std::ranges::copy(std::ranges::subrange(std::istreambuf_iterator(is), std::istreambuf_iterator<char>()) | std::views::take(rdlen), std::back_inserter(rdata));
    if (rdata.size() != rdlen) {
        ctx.log.debug("Premature EOF deserializing TXT record. {} < {}", rdata.size(), rdlen);
        return std::unexpected(make_error_code(DNSError::DeserializePrematureEOF));
    }
    auto strings = parse_character_strings(ctx, rdata);
    if (!strings) {
        return std::unexpected(strings.error());
    }
    return RData_TXT { std::move(*strings) };
}

std::expected<RData_OPT, std::error_code>
RData_OPT::deserialize(fip::context& ctx, std::istream &is, size_t rdlen)
{
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
        const auto header = load_blob<DNSOptionBlob>(ctx, loader);
        if (!header) {
            return std::unexpected(header.error());
        }
        DNSOption option { *header, {} };
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
}


std::expected<void, std::error_code>
DNSResourceRecord::serialize(fip::context& ctx, std::ostream& os) const
{
    BlobStorer storage(os);

    // Each case takes and checks its rdata before calling store_header, so a record that cannot be serialized writes nothing.
    // RDLENGTH is the size of the rdata the case writes, never the stored blob.rdlength, and is
    // refused before the name if it does not fit.
    const auto store_header = [&](size_t octets) -> std::expected<void, std::error_code> {
        const auto rdlength = rdlength_of(ctx, octets);
        if (!rdlength) {
            return std::unexpected(rdlength.error());
        }
        if (auto res = host_to_dnshost(ctx, name, os); !res) {
            return std::unexpected(res.error());
        }
        auto header = blob;
        header.rdlength = *rdlength;
        return store_blob(ctx, storage, header);
    };
    // Each case takes its rdata with std::get_if, since std::get throws for an alternative TYPE does not name.
    const auto mismatched = [&] {
        ctx.log.debug("Resource record type {} holds rdata of another type", enum_name_or_value(blob.type));
        return std::unexpected(make_error_code(DNSError::SerializeMismatchedRdata));
    };

    switch (blob.type) {
        case DNSQueryType::A: {
            const auto* a = std::get_if<RData_A>(&rdata);
            if (a == nullptr) {
                return mismatched();
            }
            if (auto res = store_header(a->ipv4_address.size()); !res) {
                return std::unexpected(res.error());
            }
            return store_bytes(a->ipv4_address, os);
        }
        case DNSQueryType::AAAA: {
            const auto* aaaa = std::get_if<RData_AAAA>(&rdata);
            if (aaaa == nullptr) {
                return mismatched();
            }
            if (auto res = store_header(aaaa->ipv6_address.size()); !res) {
                return std::unexpected(res.error());
            }
            return store_bytes(aaaa->ipv6_address, os);
        }
        case DNSQueryType::TXT: {
            const auto* txt = std::get_if<RData_TXT>(&rdata);
            if (txt == nullptr) {
                return mismatched();
            }
            if (auto oversized = std::ranges::find_if(txt->strings, [](const auto& s) { return max_character_string_octets < s.size(); });
                oversized != txt->strings.end()) {
                ctx.log.debug("TXT string too long to serialize: {} > {} bytes", oversized->size(), max_character_string_octets);
                return std::unexpected(make_error_code(DNSError::SerializeExcessiveTextSize));
            }
            if (auto res = store_header(rdata_octets(*txt)); !res) {
                return std::unexpected(res.error());
            }
            for (const auto& text : txt->strings) {
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
            const auto* opt = std::get_if<RData_OPT>(&rdata);
            if (opt == nullptr) {
                return mismatched();
            }
            if (auto res = store_header(rdata_octets(*opt)); !res) {
                return std::unexpected(res.error());
            }
            return opt->serialize(ctx, os);
        }
        default:
            ctx.log.debug("Unimplemented! Cannot serialize resource record type {}", enum_name_or_value(blob.type));
            return std::unexpected(make_error_code(DNSError::SerializeUnimplementedType));
    }
}

std::expected<DNSResourceRecord, std::error_code>
DNSResourceRecord::deserialize(fip::context& ctx, std::istream& is, jump_table_t& jump_table)
{
    BlobLoader loader(is);
    DNSResourceRecord res;

    if (auto hostname = dnshost_to_host(ctx, is, jump_table); !hostname) {
        ctx.log.debug("Failed to deserialize resource record name: {}", hostname.error().message());
        return std::unexpected(hostname.error());
    } else {
        res.name = *hostname;
    }
    ctx.log.debug("Got hostname '{}'", res.name);

    const auto header = load_blob<DNSResourceRecordBlob>(ctx, loader);
    if (!header) {
        return std::unexpected(header.error());
    }
    res.blob = *header;

    ctx.log.debug("Got blob type '{}'", enum_name_or_value(res.blob.type));

    const auto with_rdata = [&](auto rdata) -> std::expected<DNSResourceRecord, std::error_code> {
        if (!rdata) {
            return std::unexpected(rdata.error());
        }
        res.rdata = std::move(*rdata);
        return res;
    };

    switch (res.blob.type) {
        case DNSQueryType::A:
            return with_rdata(RData_A::deserialize(ctx, is, res.blob.rdlength));
        case DNSQueryType::AAAA:
            return with_rdata(RData_AAAA::deserialize(ctx, is, res.blob.rdlength));
        case DNSQueryType::TXT:
            return with_rdata(RData_TXT::deserialize(ctx, is, res.blob.rdlength));
        case DNSQueryType::OPT:
            return with_rdata(RData_OPT::deserialize(ctx, is, res.blob.rdlength));
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
}

std::expected<void, std::error_code>
DNSQuestion::serialize(fip::context& ctx, std::ostream& os) const
{
    BlobStorer storage(os);

    if (auto res = host_to_dnshost(ctx, qname, os); !res) {
        return std::unexpected(res.error());
    }
    return store_blob(ctx, storage, blob);
}

std::expected<DNSQuestion, std::error_code>
DNSQuestion::deserialize(fip::context& ctx, std::istream& is, jump_table_t& jump_table)
{
    BlobLoader loader(is);
    DNSQuestion res;

    if (auto hostname = dnshost_to_host(ctx, is, jump_table); !hostname) {
        ctx.log.debug("Failed to deserialize question name: {}", hostname.error().message());
        return std::unexpected(hostname.error());
    } else {
        res.qname = *hostname;
    }

    const auto type_and_class = load_blob<DNSQuestionBlob>(ctx, loader);
    if (!type_and_class) {
        return std::unexpected(type_and_class.error());
    }
    res.blob = *type_and_class;
    return res;
}

std::expected<void, std::error_code>
DNSMessage::serialize(std::ostream& os) const
{
    BlobStorer storage(os);

    if (auto res = store_blob(ctx, storage, header); !res) {
        return std::unexpected(res.error());
    }
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

    return {};
}

namespace {
    template <typename T>
    [[nodiscard]] std::expected<std::vector<T>, std::error_code>
    deserialize_section(fip::context& ctx, std::istream& is, jump_table_t& jump_table, uint16_t count) {
        std::vector<T> section;
        for (uint16_t i = 0; i < count; ++i) {
            auto res = T::deserialize(ctx, is, jump_table);
            if (!res) {
                return std::unexpected(res.error());
            }
            section.push_back(std::move(*res));
        }
        return section;
    }
}

std::expected<DNSMessage, std::error_code>
DNSMessage::deserialize(fip::context& ctx, std::istream& is)
{
    BlobLoader loader(is);
    DNSMessage res(ctx);
    jump_table_t jump_table;

    const auto message_header = load_blob<DNSHeader>(ctx, loader);
    if (!message_header) {
        return std::unexpected(message_header.error());
    }
    res.header = *message_header;
    ctx.log.debug("Got header {}", res.header);

    auto questions = deserialize_section<DNSQuestion>(ctx, is, jump_table, res.header.qdcount);
    if (!questions) {
        ctx.log.debug("Failed to deserialize questions: {}", questions.error().message());
        return std::unexpected(questions.error());
    }
    res.questions = std::move(*questions);
    for (const auto &q : res.questions) {
        ctx.log.debug("Got question {}", q);
    }
    auto answers = deserialize_section<DNSResourceRecord>(ctx, is, jump_table, res.header.ancount);
    if (!answers) {
        ctx.log.debug("Failed to deserialize answers: {}", answers.error().message());
        return std::unexpected(answers.error());
    }
    res.answers = std::move(*answers);
    for (const auto &q : res.answers) {
        ctx.log.debug("Got answer {}", q);
    }
    auto authorities = deserialize_section<DNSResourceRecord>(ctx, is, jump_table, res.header.nscount);
    if (!authorities) {
        ctx.log.debug("Failed to deserialize authorities: {}", authorities.error().message());
        return std::unexpected(authorities.error());
    }
    res.authorities = std::move(*authorities);
    for (const auto &q : res.authorities) {
        ctx.log.debug("Got authority {}", q);
    }
    auto additionals = deserialize_section<DNSResourceRecord>(ctx, is, jump_table, res.header.arcount);
    if (!additionals) {
        ctx.log.debug("Failed to deserialize additionals: {}", additionals.error().message());
        return std::unexpected(additionals.error());
    }
    res.additionals = std::move(*additionals);
    for (const auto &q : res.additionals) {
        ctx.log.debug("Got additional {}", q);
    }

    return res;
}
