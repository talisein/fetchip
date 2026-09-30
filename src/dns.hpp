#pragma once
#include <bit>
#include <variant>
#include <vector>
#include <expected>
#include <limits>
#include <map>
#include <ranges>
#include <string_view>

#include <magic_enum/magic_enum.hpp>
#include <magic_enum/magic_enum_flags.hpp>
#include "context.hpp"
#include "error_category.hpp"
#include "net.hpp"
#include <blobify/blobify.hpp>

using jump_table_t = std::map<uint16_t, std::string>;

template <typename E>
std::string enum_name_or_value(E value)
{
    if (auto name = magic_enum::enum_name(value); !name.empty()) {
        return std::string(name);
    }
    return std::to_string(std::to_underlying(value));
}

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
constexpr auto opcode_shift { std::countr_zero(std::to_underlying(OpCodeMask)) };

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
    OPT = 41,        // EDNS pseudo-record
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

struct DNSQuestionBlob {
    DNSQueryType qtype;     // Type of the query
    DNSQueryClass qclass;   // Class of the query
};

struct DNSQuestion {
    std::string qname;      // Domain name being queried
    DNSQuestionBlob blob;

    std::expected<void, std::error_code> serialize(fip::context& ctx, std::ostream &os) const;
    static std::expected<DNSQuestion, std::error_code> deserialize(fip::context& ctx, std::istream &is, jump_table_t& jump_table);
};

// Struct for RDATA in DNSAnswer for A (IPv4 address) records
struct RData_A {
    asio::ip::address_v4::bytes_type ipv4_address;  // IPv4 address
};

// Struct for RDATA in DNSAnswer for AAAA (IPv6 address) records
struct RData_AAAA {
    asio::ip::address_v6::bytes_type ipv6_address;  // IPv6 address
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
    std::vector<std::string> strings;  // Character-strings, in wire order
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

    std::expected<void, std::error_code> serialize(fip::context& ctx, std::ostream &os) const;
    static std::expected<RData_OPT, std::error_code> deserialize(fip::context& ctx, std::istream &is, size_t rdlen);
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

    std::expected<void, std::error_code> serialize(fip::context& ctx, std::ostream &os) const;
    static std::expected<DNSResourceRecord, std::error_code> deserialize(fip::context& ctx, std::istream &is, jump_table_t& jump_table);
};

enum class DNSError
{
    HostToDNSHostExcessiveHostLabelSize,
    HostToDNSHostExcessiveHostnameSize,
    HostToDNSHostEmptyLabel,
    SerializeStreamFailure,
    SerializeExcessiveTextSize,
    SerializeExcessiveRdataSize,
    SerializeUnimplementedType,
    SerializeMismatchedRdata,
    DeserializeStreamFailure,
    DeserializePrematureEOF,
    DeserializeInvalidValue,
    DNSHostToHostPrematureEOF,
    DNSHostToHostStreamFailure,
    DNSHostToHostExcessiveHostLabelSize,
    DNSHostToHostExcessiveHostnameSize,
    DNSHostToHostBadCompressionPointer,
    DNSResolverErrorResponse,
    DNSResolverNoAnswers,
    DNSResolverUnexpectedAnswer,
    DNSResolverWrongFamily,
    DNSResolverEmptyResponse,
    DNSResolverMismatchedResponse,
};

namespace std
{
  template <> struct is_error_code_enum<DNSError> : fip::fip_error_code
  {
  };
}

// RFC 1035 §2.3.4: a label is at most 63 octets and a name at most 255 octets on the wire.
constexpr size_t max_label_octets { 63 };
constexpr size_t max_name_octets { 255 };
// Each dot in the text stands for a length octet; the first label's length octet and the terminating zero have none.
constexpr size_t max_name_text { max_name_octets - 2 };
// RFC 1035 §3.3: a <character-string> is one length octet followed by that many octets.
constexpr size_t max_character_string_octets { std::numeric_limits<uint8_t>::max() };
// RFC 1035 §3.2.1: RDLENGTH counts the RDATA's octets in 16 bits.
constexpr size_t max_rdata_octets { std::numeric_limits<uint16_t>::max() };
// RFC 1035 §4.1.1: the header is six 16-bit fields.
constexpr size_t message_header_octets { 6 * sizeof(uint16_t) };
// RFC 1035 §4.1.4: a compression pointer is two octets, both high bits set and then a 14-bit offset.
constexpr uint8_t compression_pointer_flag { 0xC0 };
constexpr uint8_t compression_offset_high_mask { static_cast<uint8_t>(~compression_pointer_flag) };
constexpr auto compression_offset_high_shift { std::numeric_limits<uint8_t>::digits };
// RFC 1035 §4.2.1: a UDP message is at most 512 octets, and a query without an OPT record (RFC 6891) asks for no more.
constexpr size_t max_udp_message_octets { 512 };
// RFC 6891 §6.1.2: an option starts with a 16-bit OPTION-CODE and a 16-bit OPTION-LENGTH.
constexpr size_t option_header_octets { 2 * sizeof(uint16_t) };
// RFC 6891 §6.1.3: an OPT record's TTL is an 8-bit EXTENDED-RCODE, an 8-bit VERSION and 16 bits of flags, high octet first.
constexpr auto opt_ttl_version_shift { std::numeric_limits<uint16_t>::digits };
constexpr auto opt_ttl_extended_rcode_shift { opt_ttl_version_shift + std::numeric_limits<uint8_t>::digits };
static_assert(opt_ttl_extended_rcode_shift + std::numeric_limits<uint8_t>::digits == std::numeric_limits<decltype(DNSResourceRecordBlob::ttl)>::digits);

[[nodiscard]] constexpr std::expected<void, std::error_code>
validate_dns_name(std::string_view name) noexcept
{
    using namespace std::literals;

    if (max_name_text < name.size()) {
        return std::unexpected(make_error_code(DNSError::HostToDNSHostExcessiveHostnameSize));
    }
    // "" splits into no labels: it is the root, the name dnshost_to_host reads from a lone zero octet.
    for (const auto& label : std::views::split(name, "."sv)) {
        // RFC 1034 §3.1: the null label is reserved for the root.
        if (std::ranges::empty(label)) {
            return std::unexpected(make_error_code(DNSError::HostToDNSHostEmptyLabel));
        }
        if (max_label_octets < std::ranges::size(label)) {
            return std::unexpected(make_error_code(DNSError::HostToDNSHostExcessiveHostLabelSize));
        }
    }
    return {};
}

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
    [[nodiscard]] std::expected<void, std::error_code> serialize(std::ostream& os) const;
    [[nodiscard]] static std::expected<DNSMessage, std::error_code> deserialize(fip::context& ctx, std::istream& os);

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

#include "dns_formatters.hpp"
#include "dns_blobify.hpp"
