#pragma once

#include <format>
#include <ranges>
#include "dns.hpp"

template <>
struct std::formatter<DNSHeaderFlags> {
    constexpr auto parse(format_parse_context& ctx) {
        return ctx.begin();
    }
    template <typename FormatContext>
    auto format(DNSHeaderFlags p, FormatContext& ctx) const {
        const DNSHeaderFlags masked_flags = static_cast<DNSHeaderFlags>(p & static_cast<DNSHeaderFlags>(~(OpCodeMask | ResponseCodeMask | QueryResponse)));
        const auto op_code = static_cast<DNSOpCodes>((p & OpCodeMask) >> 11);
        const auto response_code = static_cast<DNSResponseCodes>(p & ResponseCodeMask);
        return format_to(ctx.out(), "DNSHeaderFlags {{ QR: {}, Flags: {}, OpCode: {}, ResponseCode: {} }}",
                         (QueryResponse & p) ? "Response"sv : "Query"sv,
                         magic_enum::enum_flags_name(masked_flags),
                         magic_enum::enum_name(op_code),
                         magic_enum::enum_name(response_code));
    }
};


template <>
struct std::formatter<DNSHeader> {
    constexpr auto parse(format_parse_context& ctx) {
        return ctx.begin();
    }
    template <typename FormatContext>
    auto format(const DNSHeader& p, FormatContext& ctx) const {
        return format_to(ctx.out(), "DNSHeader {{ ID: 0x{:X}, {}, Questions: {}, Answers: {}, Authorities: {}, Additionals: {} }}"sv,
                         p.id, p.flags, p.qdcount, p.ancount, p.nscount, p.arcount);
    }
};


template <>
struct std::formatter<DNSQuestion> {
    constexpr auto parse(format_parse_context& ctx) {
        return ctx.begin();
    }
    template <typename FormatContext>
    auto format(const DNSQuestion& p, FormatContext& ctx) const {
        return format_to(ctx.out(), "DNSQuestion {{ Name: {}, Type: {}, Class: {} }}"sv,
                         p.qname, magic_enum::enum_name(p.blob.qtype), magic_enum::enum_name(p.blob.qclass));
    }
};

template <>
struct std::formatter<RData_A> {
    constexpr auto parse(format_parse_context& ctx) {
        return ctx.begin();
    }
    template <typename FormatContext>
    auto format(RData_A p, FormatContext& ctx) const {
        return format_to(ctx.out(), "RData_A {{ ipv4_address: {} }}"sv, asio::ip::address_v4(p.ipv4_address.s_addr).to_string());
    }
};

template <>
struct std::formatter<RData_AAAA> {
    constexpr auto parse(format_parse_context& ctx) {
        return ctx.begin();
    }
    template <typename FormatContext>
    auto format(const RData_AAAA& p, FormatContext& ctx) const {
        return format_to(ctx.out(), "RData_AAAA {{ ipv6_address: {} }}"sv, asio::ip::address_v6(std::to_array(p.ipv6_address.s6_addr)).to_string());
    }
};

template <>
struct std::formatter<RData_OPT> {
    constexpr auto parse(format_parse_context& ctx) {
        return ctx.begin();
    }
    template <typename FormatContext>
    auto format(const RData_OPT& p, FormatContext& ctx) const {
        auto out_iter = ctx.out();
        for (const auto& option : p.options) {
            out_iter = format_to(out_iter, ", EDNS0_Option {{ OptionCode: {}, OptionDataSize: {}, Data: {{ 0x",
                                 enum_name_or_value(option.blob.option_code), option.blob.data_size);
            for (const auto c : option.data) {
                out_iter = format_to(out_iter, "{:02X}", c);
            }
            out_iter = format_to(out_iter, " }} }}"); // option.data
        }
        return out_iter;
    }
};

template <>
struct std::formatter<DNSResourceRecord> {
    constexpr auto parse(format_parse_context& ctx) {
        return ctx.begin();
    }
    template <typename FormatContext>
    auto format(const DNSResourceRecord& rr, FormatContext& ctx) const
    {
        if (rr.blob.type != DNSQueryType::OPT) {
            auto out_iter = format_to(ctx.out(),
                                      "DNSResourceRecord {{ Name: {}, Type: {}, Class: {}, TTL: {}, RDataLength: {}, "sv,
                                      rr.name,
                                      enum_name_or_value(rr.blob.type),
                                      magic_enum::enum_name(rr.blob.query_class),
                                      rr.blob.ttl,
                                      rr.blob.rdlength);
            switch (rr.blob.type) {
                case DNSQueryType::A:
                    return format_to(out_iter, "{} }}", std::get<RData_A>(rr.rdata));
                case DNSQueryType::AAAA:
                    return format_to(out_iter, "{} }}", std::get<RData_AAAA>(rr.rdata));
                case DNSQueryType::TXT:
                    return format_to(out_iter, "RData_TXT: {} }}", std::get<RData_TXT>(rr.rdata).strings | std::views::join_with(' ') | std::ranges::to<std::string>());
                default:
                    return format_to(out_iter, "(unimplemented rdata formatter) }}");
            }
        } else {
            EDNS_ResourceRecord edns {rr.blob};
            auto flags = std::string(magic_enum::enum_flags_name(edns.flags));
            if (flags.empty())
                flags = std::format("{:#06x}", std::to_underlying(edns.flags));

            auto out_iter = format_to(ctx.out(), "EDNS_ResourceRecord {{ Type: {}, UDP_PayloadSize: {}, ExtendedRCode: {}, Version: {}, Flags: {}, RDataLength: {}"sv,
                                      magic_enum::enum_name(edns.type),
                                      edns.payload_size,
                                      edns.extendedRCode,
                                      edns.version,
                                      flags,
                                      edns.rdlength);
            return format_to(out_iter, "{} }}", std::get<RData_OPT>(rr.rdata));
        }
    }
};

template <>
struct std::formatter<DNSMessage> {
    constexpr auto parse(format_parse_context& ctx) {
        return ctx.begin();
    }
    template <typename FormatContext>
    auto format(const DNSMessage& p, FormatContext& ctx) const {
        auto out_iter = format_to(ctx.out(), "DNSMessage {{ {}, ", p.get_header());

        auto writer = [&out_iter, is_first = true](const auto& rr) mutable {
            if (is_first) {
                out_iter = format_to(out_iter, "{}", rr);
                is_first = false;
            } else {
                out_iter = format_to(out_iter, ", {}", rr);
            }
        };
        std::ranges::for_each(p.get_questions(), std::ref(writer));
        std::ranges::for_each(p.get_answers(), std::ref(writer));
        std::ranges::for_each(p.get_authorities(), std::ref(writer));
        std::ranges::for_each(p.get_additionals(), std::ref(writer));

        return format_to(out_iter, " }}");
    }
};
