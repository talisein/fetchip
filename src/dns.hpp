#pragma once
#include <format>
#include <variant>
#include <vector>
#include <expected>
#include <map>
#include <sys/socket.h>

#include <magic_enum.hpp>
#include <magic_enum_flags.hpp>
#include "context.hpp"
#include <blobify/blobify.hpp>

constexpr size_t DNSBufferSize { 1410 };

using jump_table_t = std::map<uint16_t, std::string>;

enum DNSHeaderFlags : uint16_t {
    QueryResponse = 1 << 15,     // Query or Response (1 for response, 0 for query)
    OpCodeB3 = 1 << 14,          // Opcode
    OpCodeB2 = 1 << 13,          // Opcode
    OpCodeB1 = 1 << 12,          // Opcode
    OpCodeB0 = 1 << 11,          // Opcode
    Authoritative = 1 << 10,     // Authoritative Answer
    Truncated = 1 << 9,          // Truncated
    RecursionDesired = 1 << 8,   // Recursion Desired
    RecursionAvailable = 1 << 7, // Recursion Available
    ZReserved = 1 << 6,          // Reserved (must be zero)
    AuthenticatedData = 1 << 5,  // Authenticated Data (DNSSEC)
    CheckingDisabled = 1 << 4,   // Checking Disabled (DNSSEC)
    ResponseCodeB3 = 1 << 3,
    ResponseCodeB2 = 1 << 2,
    ResponseCodeB1 = 1 << 1,
    ResponseCodeB0 = 1 << 0,
};

template <>
struct magic_enum::customize::enum_range<DNSHeaderFlags> {
  static constexpr bool is_flags = true;
};

constexpr DNSHeaderFlags OpCodeMask       = (DNSHeaderFlags)(DNSHeaderFlags::OpCodeB0 | DNSHeaderFlags::OpCodeB1 | DNSHeaderFlags::OpCodeB2 | DNSHeaderFlags::OpCodeB3);
constexpr DNSHeaderFlags ResponseCodeMask = (DNSHeaderFlags)(DNSHeaderFlags::ResponseCodeB0 | DNSHeaderFlags::ResponseCodeB1 | DNSHeaderFlags::ResponseCodeB2 | DNSHeaderFlags::ResponseCodeB3);

enum class DNSOpCodes : uint8_t {
    STANDARD_QUERY = 0,
    INVERSE_QUERY = 1,
    SERVER_STATUS_REQUEST = 2,
    RESERVED_3 = 3,
    NOTIFY = 4,
    UPDATE = 5,
    DNS_STATEFUL_OPERATIONS = 6,
    RESERVED_7 = 7,
    RESERVED_8 = 8,
    RESERVED_9 = 9,
    RESERVED_10 = 10,
    RESERVED_11 = 11,
    RESERVED_12 = 12,
    RESERVED_13 = 13,
    RESERVED_14 = 14,
    RESERVED_15 = 15,
};

enum class DNSResponseCodes : uint8_t {
    NO_ERROR = 0,
    FORMAT_ERROR = 1,
    SERVER_ERROR = 2,
    NAME_ERROR = 3, // Non-Existant Domain
    NOT_IMPLEMENTED = 4,
    REFUSED = 5,
    YXDOMAIN = 6, // Name Exists when it should not
    YXRRSET = 7,
    NXRRSET = 8,
    NOT_AUTHORIZED = 9,
    NOT_ZONE = 10,
    DSOTYPENI = 11,
    RESERVED_12 = 12,
    RESERVED_13 = 13,
    RESERVED_14 = 14,
    RESERVED_15 = 15,
};

enum class DNSExtResponseCodes : uint16_t {
    NO_ERROR = 0,
    FORMAT_ERROR = 1,
    SERVER_ERROR = 2,
    NAME_ERROR = 3, // Non-Existant Domain
    NOT_IMPLEMENTED = 4,
    REFUSED = 5,
    YXDOMAIN = 6, // Name Exists when it should not
    YXRRSET = 7,
    NXRRSET = 8,
    NOT_AUTHORIZED = 9,
    NOT_ZONE = 10,
    DSOTYPENI = 11,
    RESERVED_12 = 12,
    RESERVED_13 = 13,
    RESERVED_14 = 14,
    RESERVED_15 = 15,
    BADVERS_OR_BADSIG = 16,
    BADKEY = 17,
    BADTIME = 18,
    BADMODE = 19,
    BADNAME = 20,
    BADALG = 21,
    BADTRUNC = 22,
    BADCOOKIE = 23,
    RESERVED = 65535
};

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


enum class DNSQueryType : uint16_t {
    A = 1,           // IPv4 address
    NS = 2,          // Name Server
    MD = 3,          // obsolete - mail destination
    MF = 4,          // obsolete - mail forwarder
    CNAME = 5,       // Canonical Name
    SOA = 6,         // Start of Authority
    MB = 7,          // experimental - mailbox domain
    MG = 8,          // experimental - mail group member
    MR = 9,          // experimental - mail rename domain name
    NULL_ = 10,      // a null RR
    WKS = 11,        // Well known service description
    PTR = 12,        // Pointer
    HINFO = 13,      // Host information
    MINFO = 14,      // mail list information
    MX = 15,         // Mail Exchange
    TXT = 16,        // Text
    AAAA = 28,       // IPv6 address
    SRV = 33,        // Service location
    OPT = 41,        // Any type (query for any type)
    ANY = 255,       // Any type (query for any type)
};

enum class DNSQueryClass : uint16_t {
    IN = 1,      // Internet (default and most commonly used)
    CS = 2,      // CSNET (historical)
    CHAOS = 3,      // Chaos (historical)
    HS = 4,      // Hesiod (historical)
    ANY = 255    // Any class (query for any class)
};

struct DNSHeader {
    uint16_t id;       // 16-bit identifier assigned by the program
    DNSHeaderFlags flags;  // Flags field, containing control information
    uint16_t qdcount;  // Number of entries in the question section
    uint16_t ancount;  // Number of resource records in the answer section
    uint16_t nscount;  // Number of name server resource records in the authority records section
    uint16_t arcount;  // Number of resource records in the additional records section

    DNSResponseCodes get_response_code() const {
        return *magic_enum::enum_cast<DNSResponseCodes>(flags & ResponseCodeMask);
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


struct DNSQuestionBlob {
    DNSQueryType qtype;     // Type of the query
    DNSQueryClass qclass;   // Class of the query
};

struct DNSQuestion {
    std::string qname;      // Domain name being queried
    DNSQuestionBlob blob;

    std::expected<void, std::error_code> serialize(fip::context& ctx, std::ostream &os) const noexcept;
    static std::expected<DNSQuestion, std::error_code> deserialize(fip::context& ctx, std::istream &is, jump_table_t& jump_table) noexcept;
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

// Struct for RDATA in DNSAnswer for A (IPv4 address) records
struct RData_A {
    in_addr ipv4_address;  // IPv4 address
};

// Struct for RDATA in DNSAnswer for AAAA (IPv6 address) records
struct RData_AAAA {
    in6_addr ipv6_address;  // IPv6 address
};

template <>
struct std::formatter<RData_A> {
    constexpr auto parse(format_parse_context& ctx) {
        return ctx.begin();
    }
    template <typename FormatContext>
    auto format(RData_A p, FormatContext& ctx) const {
        std::array<char, INET_ADDRSTRLEN + 1> buf;
        auto res = inet_ntop(AF_INET, &p.ipv4_address, buf.data(), buf.size());
        if (res) {
            return format_to(ctx.out(), "RData_A {{ ipv4_address: {} }}"sv, buf.begin());
        } else {
            return format_to(ctx.out(), "RData_A {{ ipv4_address: (Error: {}) }}"sv, strerror(errno));
        }
    }
};

template <>
struct std::formatter<RData_AAAA> {
    constexpr auto parse(format_parse_context& ctx) {
        return ctx.begin();
    }
    template <typename FormatContext>
    auto format(const RData_AAAA& p, FormatContext& ctx) const {
        std::array<char, INET6_ADDRSTRLEN + 1> buf;
        auto res = inet_ntop(AF_INET6, &p.ipv6_address, buf.data(), buf.size());
        if (res) {
            return format_to(ctx.out(), "RData_AAAA {{ ipv6_address: {} }}"sv, buf.begin());
        } else {
            return format_to(ctx.out(), "RData_AAAA {{ ipv6_address: (Error: {}) }}"sv, strerror(errno));
        }
    }
};

// Struct for RDATA in DNSAnswer for NS (Name Server) records
struct RData_NS {
    std::string nsdname;  // Name Server domain name
};

// Struct for RDATA in DNSAnswer for CNAME (Canonical Name) records
struct RData_CNAME {
    std::string cname;  // Canonical Name
};

// Struct for RDATA in DNSAnswer for MX (Mail Exchange) records
struct RData_MX {
    uint16_t preference;  // Preference value
    std::string exchange; // Mail Exchange domain name
};

// Struct for RDATA in DNSAnswer for TXT (Text) records
struct RData_TXT {
    std::string text;  // Text data
};

// Struct for RDATA in DNSAnswer for SRV (Service location) records
struct RData_SRV {
    uint16_t priority;  // Priority
    uint16_t weight;    // Weight
    uint16_t port;      // Port
    std::string target; // Target domain name
};

// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11
enum class EDNSOptionCode : uint16_t {
    Reserved0 = 0,
    LLQ = 1,                 // Long-Lived Queries (RFC 8764)
    UL = 2,                  // Update Lease (RFC 6891)
    NSID = 3,                // Name Server Identifier (RFC 5001)
    Reserved4 = 4,
    DAU = 5,                 // DNSSEC Algorithm Understood (RFC 6975)
    DHU = 6,                 // DNSSEC Algorithm Understood (RFC 6975)
    N3U = 7,                 // DNSSEC Algorithm Understood (RFC 6975)
    EDNS_Client_Subnet = 8,  // RFC 7871
    EDNS_Expire = 9,         // 7314
    COOKIE = 10,             // 7873
    EDNS_TCP_KeepAlive = 11, // 7828
    Padding = 12,            // Padding (RFC 7830)
    CHAIN = 13,              // 7901
    EDNS_Key_Tag = 14,       // 8145
    EDNS_Error = 15,         // 8914
    EDNS_Client_Tag = 16,    // https://www.iana.org/go/draft-bellis-dnsop-edns-tags
    EDNS_Server_Tag = 17,    // https://www.iana.org/go/draft-bellis-dnsop-edns-tags
//    Umbrella_Indent = 20292, // Cisco
//    Device_ID = 26946,
};

enum class DNSOptFlags : uint16_t {
    DO = 0x8000,  // DNSSEC OK flag
};

template <>
struct magic_enum::customize::enum_range<DNSOptFlags> {
  static constexpr bool is_flags = true;
};

struct DNSOptionBlob {
    EDNSOptionCode option_code;  // Option code
    uint16_t data_size;      // Length of the option data
};

struct DNSOption {
    DNSOptionBlob blob;
    std::vector<uint8_t> data;  // Option data
};

struct RData_OPT {
    std::vector<DNSOption> options; // octet stream of {attribute, value} pairs

    std::expected<void, std::error_code> serialize(fip::context& ctx, std::ostream &os) const noexcept;
    static std::expected<RData_OPT, std::error_code> deserialize(fip::context& ctx, std::istream &is, size_t rdlen) noexcept;
};

template <>
struct std::formatter<RData_OPT> {
    constexpr auto parse(format_parse_context& ctx) {
        return ctx.begin();
    }
    template <typename FormatContext>
    auto format(const RData_OPT& p, FormatContext& ctx) const {
        auto out_iter = ctx.out();
        for (auto option : p.options) {
            out_iter = format_to(out_iter, ", EDNS0_Option {{ OptionCode: {}, OptionDataSize: {}, Data: {{ 0x",
                                 magic_enum::enum_name(option.blob.option_code), option.blob.data_size);
            for (auto c : option.data) {
                out_iter = format_to(out_iter, "{:X}", c);
            }
            out_iter = format_to(out_iter, " }} }}"); // option.data
        }
        return out_iter;
    }
};


struct DNSResourceRecordBlob {
    DNSQueryType type;   // Type of the query response
    DNSQueryClass query_class; // Class of the query response
    uint32_t ttl;        // Time to live (how long the resource record can be cached)
    uint16_t rdlength;   // Length of the RDATA field
};

struct EDNS_ResourceRecord {
    EDNS_ResourceRecord(const DNSResourceRecordBlob& rr);

    DNSQueryType type;     // 41
    uint16_t payload_size; // 'Class'
    /* Begin 'TTL' */
    uint8_t extendedRCode; // Extended Response Code
    uint8_t version;
    DNSOptFlags flags;
    /* End 'TTL' */
    uint16_t rdlength;        // length of all rdata
};

struct DNSResourceRecord {
    using RDataVariant_t = std::variant<RData_A, RData_AAAA, RData_NS, RData_CNAME, RData_MX, RData_TXT, RData_SRV, RData_OPT>;

    std::string name;
    DNSResourceRecordBlob blob;
    RDataVariant_t rdata;

    std::expected<void, std::error_code> serialize(fip::context& ctx, std::ostream &os) const noexcept;
    static std::expected<DNSResourceRecord, std::error_code> deserialize(fip::context& ctx, std::istream &is, jump_table_t& jump_table) noexcept;
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
                                      magic_enum::enum_name(rr.blob.type),
                                      magic_enum::enum_name(rr.blob.query_class),
                                      rr.blob.ttl,
                                      rr.blob.rdlength);
            switch (rr.blob.type) {
                case DNSQueryType::A:
                    return format_to(out_iter, "{} }}", std::get<RData_A>(rr.rdata));
                case DNSQueryType::AAAA:
                    return format_to(out_iter, "{} }}", std::get<RData_AAAA>(rr.rdata));
                case DNSQueryType::TXT:
                    return format_to(out_iter, "RData_TXT: {} }}", std::get<RData_TXT>(rr.rdata).text);
                default:
                    return format_to(out_iter, "(unimplemented rdata formatter) }}");
            }
        } else {
            EDNS_ResourceRecord edns {rr.blob};

            auto out_iter = format_to(ctx.out(), "EDNS_ResourceRecord {{ Type: {}, UDP_PayloadSize: {}, ExtendedRCode: {}, Version: {}, Flags: {}, RDataLength: {}"sv,
                                      magic_enum::enum_name(edns.type),
                                      edns.payload_size,
                                      edns.extendedRCode,
                                      edns.version,
                                      magic_enum::enum_flags_name(edns.flags),
                                      edns.rdlength);
            return format_to(out_iter, "{} }}", std::get<RData_OPT>(rr.rdata));
        }
    }
};

enum class DNSError
{
    BlobifyStore,
    HostToDNSHostStreamUnexpectedException,
    HostToDNSHostStreamFailure,
    SerializeUnexpectedException,
    SerializeStreamFailure,
    DeserializeUnexpectedException,
    DeserializeStreamFailure,
    DeserializeUnimplementedQueryType,
    DeserializePrematureEOF,
    DNSHostToHostNullHostname,
    DNSHostToHostPrematureEOF,
    DNSHostToHostStreamFailure,
    DNSHostToHostExcessiveHostLabelSize,
    DNSHostToHostZeroHostLabelSize,
    DNSHostToHostExcessiveHostnameSize,
    DNSHostToHostNonnumericLabelSize,
    DNSHostToHostStreamUnexpectedException,
    DNSResolverErrorResponse,
    DNSResolverNoAnswers,
    DNSResolverUnexpectedAnswer,
};

namespace std
{
  template <> struct is_error_code_enum<DNSError> : true_type
  {
  };
}

namespace detail
{
    class DNSError_category : public std::error_category
    {
    public:
        virtual const char *name() const noexcept override final { return "DNSError"; }
        virtual std::string message(int c) const override final
        {
            using namespace std::string_view_literals;
            return std::string(magic_enum::enum_cast<DNSError>(c).
                               transform(&magic_enum::enum_name<DNSError>).
                               value_or("Unknown DNSError"sv));
        }

        virtual std::error_condition default_error_condition(int c) const noexcept override final
        {
            return std::error_condition(c, *this);
        }
    };
}

const detail::DNSError_category& DNSError_category();
std::error_code make_error_code(DNSError e);

[[nodiscard]] std::expected<void, std::error_code> host_to_dnshost(fip::context& ctx, std::string_view hostname, std::ostream& os) noexcept;
[[nodiscard]] std::expected<std::string, std::error_code> dnshost_to_host(fip::context& ctx, std::istream& is, jump_table_t& jump_table) noexcept;


class DNSMessage
{
    DNSHeader header;
    std::vector<DNSQuestion> questions;
    std::vector<DNSResourceRecord> answers;
    std::vector<DNSResourceRecord> authorities;
    std::vector<DNSResourceRecord> additionals;

    fip::context& ctx;

public:
    DNSMessage(fip::context& ctx) noexcept;
    [[nodiscard]] std::expected<void, std::error_code> serialize(std::ostream& os) const noexcept;
    [[nodiscard]] static std::expected<DNSMessage, std::error_code> deserialize(fip::context& ctx, std::istream& os) noexcept;

    void add_question(std::string_view hostname, DNSQueryType qtype) { questions.emplace_back(std::string(hostname), DNSQuestionBlob{qtype, DNSQueryClass::IN}); ++header.qdcount; }

    template <typename RR>
    void add_question(RR&& rr) { questions.push_back(std::forward<RR>(rr)); ++header.qdcount; };
    template <typename RR>
    void add_answer(RR&& rr) { answers.push_back(std::forward<RR>(rr)); ++header.ancount; };
    template <typename RR>
    void add_authority(RR&& rr) { authorities.push_back(std::forward<RR>(rr)); ++header.nscount; };
    template <typename RR>
    void add_additional(RR&& rr) { additionals.push_back(std::forward<RR>(rr)); ++header.arcount; };
    [[nodiscard]] DNSHeader get_header() const noexcept { return header; };
    [[nodiscard]] std::span<const DNSQuestion> get_questions() const noexcept { return questions; };
    [[nodiscard]] std::span<const DNSResourceRecord> get_answers() const noexcept { return answers; };
    [[nodiscard]] std::span<const DNSResourceRecord> get_authorities() const noexcept { return authorities; };
    [[nodiscard]] std::span<const DNSResourceRecord> get_additionals() const noexcept { return additionals; };
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
