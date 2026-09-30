#include <algorithm>
#include <bit>
#include <spanstream>
#include <sstream>
#include <ranges>
#include <utility>
#include <boost/ut.hpp>
#include <arpa/inet.h>
#include <magic_enum/magic_enum.hpp>
#include <magic_enum/magic_enum_flags.hpp>
#include <magic_enum/magic_enum_iostream.hpp>
#include "dns.hpp"
#include "dns_resolver.hpp"

template<size_t fail_count>
class throws_after_failcount_streambuf : public std::basic_streambuf<char> {
public:
    std::string str;
    std::string::const_iterator it;
    size_t count;
    size_t local_fail_count;
    throws_after_failcount_streambuf(std::string_view in = {}, size_t local_fail_count = fail_count) :
        std::basic_streambuf<char>(),
        str(in),
        it(str.cbegin()),
        count(0),
        local_fail_count(local_fail_count)
    {
    }
    throws_after_failcount_streambuf(const throws_after_failcount_streambuf&) = delete;
    throws_after_failcount_streambuf& operator=(const throws_after_failcount_streambuf&) = delete;

    virtual std::basic_streambuf<char>::int_type uflow() override {
        if (local_fail_count < count++) throw std::runtime_error("mock stream failure");
        if (it == str.cend()) return std::basic_streambuf<char>::traits_type::eof();
        return std::basic_streambuf<char>::traits_type::to_int_type(*it++);
    }

    virtual std::basic_streambuf<char>::int_type underflow() override {
        if (local_fail_count < count) throw std::runtime_error("mock stream failure");
        if (it == str.cend()) return std::basic_streambuf<char>::traits_type::eof();
        return std::basic_streambuf<char>::traits_type::to_int_type(*it);
    }

    virtual int_type overflow( int_type ch  ) override {
        if (local_fail_count < count++) {
            throw std::runtime_error("overflow");
        }
        return 1;
    }

    // tellg() asks for the current offset; a name's compression pointers need it.
    virtual pos_type seekoff(off_type off, std::ios_base::seekdir dir, std::ios_base::openmode) override {
        if (off != 0 || dir != std::ios_base::cur) {
            return pos_type(off_type(-1));
        }
        return pos_type(std::ranges::distance(str.cbegin(), it));
    }
};

std::string big_endian(uint16_t value)
{
    return std::ranges::to<std::string>(std::bit_cast<std::array<char, sizeof value>>(htons(value)));
}

std::string with_id(std::string_view response, uint16_t id)
{
    return big_endian(id) + std::ranges::to<std::string>(response | std::views::drop(sizeof(DNSHeader::id)));
}

std::string with_id(std::string_view response, const DNSMessage& query)
{
    return with_id(response, query.get_header().id);
}

int main() {
    using namespace boost::ut;
    using namespace std::string_literals;
    using namespace std::string_view_literals;

    "serialize question"_test = [] (const auto &pair) {
        const auto &[host, dnshost] = pair;
        fip::context ctx{39, true};

        for (auto qtype : magic_enum::enum_values<DNSQueryType>()) {
            for (auto qclass : magic_enum::enum_values<DNSQueryClass>()) {
                DNSQuestion question { std::string(host), { qtype, qclass } };
                std::array <char, 100> buf;
                std::ranges::fill(buf, 0xff);
                std::ospanstream ss(buf);

                auto res = question.serialize(ctx, ss);
                expect(res.has_value()) << std::format("{} what: {}", host, res.has_value() ? "noerror" : res.error().message());
                expect(eq(std::string_view(ss.span()),
                          std::string(dnshost) + big_endian(std::to_underlying(qtype)) + big_endian(std::to_underlying(qclass)))) << host;
            }
        }
    } | std::vector<std::pair<std::string_view, std::string_view>> {
        {"www.example.com"sv,                         "\x03www\007example\003com\0"sv},
        {"sub.domain.com"sv,                          "\x03sub\006domain\003com\0"sv},
        {"localhost"sv,                               "\x09localhost\0"sv},
        {"api.ipify.org"sv,                           "\003api\x05ipify\x03org\0"sv},
        {"ifconfig.me"sv,                             "\x08ifconfig\x02me\0"sv},
        {"icanhazip.com"sv,                           "\x09icanhazip\003com\0"sv},
        {"averylonghostname.com"sv,                   "\021averylonghostname\003com\0"sv},
        {"verylonghostname.averylonghostname.com"sv,  "\020verylonghostname\021averylonghostname\3com\0"sv},
        {"123.456.com"sv,                             "\003123\003456\003com\0"sv},
        // The root name.
        {""sv,                                        "\0"sv},
    };

    "question serialization failures"_test = [] (const auto &in) {
        const auto &[host, error] = in;
        fip::context ctx{39, true};
        DNSQuestion question { std::string(host), { DNSQueryType::A, DNSQueryClass::IN } };
        // This array is too short -> StreamFailure
        std::array <char, 20> buf;
        std::ranges::fill(buf, 0xff);
        std::ospanstream ss(buf);

        auto result = question.serialize(ctx, ss);
        expect(!result.has_value());
        expect(eq(result.error(), error));
    } | std::vector<std::pair<std::string_view, DNSError>> {
        // A 40-octet label overflows the buffer mid-label.
        {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"sv, DNSError::SerializeStreamFailure},
        // A 19-octet label fills the buffer, so the next length octet is the short write.
        {"abcdefghijklmnopqrs.com"sv, DNSError::SerializeStreamFailure},
        // Likewise the terminating zero.
        {"abcdefghijklmnopqrs"sv, DNSError::SerializeStreamFailure},
    };

    "question serialization empty labels"_test = [] (const auto &host) {
        fip::context ctx{39, true};
        DNSQuestion question { std::string(host), { DNSQueryType::A, DNSQueryClass::IN } };
        std::array <char, 100> buf;
        std::ranges::fill(buf, 0xff);
        std::ospanstream ss(buf);

        auto result = question.serialize(ctx, ss);
        expect(!result.has_value()) << host;
        if (!result.has_value()) {
            expect(eq(result.error(), DNSError::HostToDNSHostEmptyLabel)) << host;
        }
        // Refused before the first length octet, so no stray zero octet reaches the wire.
        expect(ss.span().empty()) << host;
    } | std::vector<std::string_view> {
        "."sv,
        "a."sv,
        ".a"sv,
        "a..b"sv,
        "example.com."sv,
    };

    "validate dns name"_test = [] (const auto &pair) {
        const auto &[name, want] = pair;
        expect(validate_dns_name(name) == want) << name;
    } | std::vector<std::pair<std::string, std::expected<void, std::error_code>>> {
        // The root name.
        {""s, {}},
        {"a"s, {}},
        {"."s, std::unexpected(make_error_code(DNSError::HostToDNSHostEmptyLabel))},
        {"a."s, std::unexpected(make_error_code(DNSError::HostToDNSHostEmptyLabel))},
        {".a"s, std::unexpected(make_error_code(DNSError::HostToDNSHostEmptyLabel))},
        {"a..b"s, std::unexpected(make_error_code(DNSError::HostToDNSHostEmptyLabel))},
        // The limits are spelled out, not taken from the constants under test.
        {std::string(63, 'a'), {}},
        {std::string(64, 'a'), std::unexpected(make_error_code(DNSError::HostToDNSHostExcessiveHostLabelSize))},
        // 253 text characters, a 255-octet name.
        {std::format("{0}.{0}.{0}.{1}", std::string(63, 'a'), std::string(61, 'b')), {}},
        // 254 text characters, a 256-octet name.
        {std::format("{0}.{0}.{0}.{1}", std::string(63, 'a'), std::string(62, 'b')), std::unexpected(make_error_code(DNSError::HostToDNSHostExcessiveHostnameSize))},
    };

    "question serialization exception"_test = [] (const auto &in) {
        const auto &[host, error] = in;
        fip::context ctx{39, true};
        DNSQuestion question { std::string(host), { DNSQueryType::A, DNSQueryClass::IN } };
        // The name fits, so it is the blob's write that the stream throws from.
        std::array <char, 20> buf;
        std::ranges::fill(buf, 0xff);
        std::ospanstream ss(buf);
        ss.exceptions(std::ios_base::badbit | std::ios_base::failbit);

        auto result = question.serialize(ctx, ss);
        expect(!result.has_value());
        expect(eq(result.error(), error));
    } | std::vector<std::pair<std::string_view, std::error_code>> {
        {"www.example.com"sv, std::make_error_code(std::io_errc::stream)},
    };

    "query serialize failures"_test = [] (const auto &in) {
        const auto &[host, error] = in;
        fip::context ctx{39, true};
        DNSMessage message {ctx};
        message.add_question(host, DNSQueryType::A);
        throws_after_failcount_streambuf<1> buf;
        std::ostream ss(&buf);

        auto result = message.serialize(ss);
        expect(!result.has_value());
        expect(eq(result.error(), error));
    } | std::vector<std::pair<std::string_view, DNSError>> {
        {"www.example.com"sv, DNSError::SerializeStreamFailure},
    };

    "query serialize exception"_test = [] (const auto &in) {
        const auto &[host, error] = in;
        fip::context ctx{39, true};
        DNSMessage message {ctx};
        message.add_question(host, DNSQueryType::A);
        throws_after_failcount_streambuf<1> buf;
        std::ostream ss(&buf);
        ss.exceptions(std::ios_base::badbit | std::ios_base::failbit);

        auto result = message.serialize(ss);
        expect(!result.has_value());
        expect(eq(result.error(), error));
    } | std::vector<std::pair<std::string_view, DNSError>> {
        {"www.example.com"sv, DNSError::SerializeUnexpectedException},
    };


    "question deserialize"_test = [] (const auto &pair){
        const auto &[dnshost, host] = pair;
        fip::context ctx(39, true);
        std::ispanstream ss(dnshost);
        jump_table_t jt;
        const auto result = DNSQuestion::deserialize(ctx, ss, jt);
        expect(result.has_value()) << dnshost;
        if (result.has_value()) {
            expect(eq(result->qname, host)) << dnshost;
        } else {
            boost::ut::log("{}", result.error().message());
        }
    } | std::vector<std::pair<std::string_view, std::string_view>> {
        {"\x03www\007example\003com\0\x00\x01\x00\x01"sv,                        "www.example.com"sv},
        {"\x03sub\006domain\003com\0\x00\x01\x00\x01"sv,                         "sub.domain.com"sv},
        {"\x09localhost\0\x00\x01\x00\x01"sv,                                    "localhost"sv},
        {"\003api\x05ipify\x03org\0\x00\x01\x00\x01"sv,                          "api.ipify.org"sv},
        {"\x08ifconfig\x02me\0\x00\x01\x00\x01"sv,                               "ifconfig.me"sv},
        {"\x09icanhazip\003com\0\x00\x01\x00\x01"sv,                             "icanhazip.com"sv},
        {"\021averylonghostname\003com\0\x00\x01\x00\x01"sv,                     "averylonghostname.com"sv},
        {"\020verylonghostname\021averylonghostname\003com\0\x00\x01\x00\x01"sv, "verylonghostname.averylonghostname.com"sv},
        {"\077x23456789012345678901234567890123456789012345678901234567890123\077y23456789012345678901234567890123456789012345678901234567890123\077z23456789012345678901234567890123456789012345678901234567890123\075a234567890123456789012345678901234567890123456789012345678901\0\x00\x01\x00\x01"sv,
         "x23456789012345678901234567890123456789012345678901234567890123.y23456789012345678901234567890123456789012345678901234567890123.z23456789012345678901234567890123456789012345678901234567890123.a234567890123456789012345678901234567890123456789012345678901"sv}
    };

    "question deserialize compressed"_test = [] (const auto &pair) {
        const auto &[wire, hosts] = pair;
        fip::context ctx(39, true);
        std::ispanstream ss(wire);
        jump_table_t jt;

        for (const auto host : hosts) {
            const auto result = DNSQuestion::deserialize(ctx, ss, jt);
            expect(result.has_value()) << wire << host;
            if (result.has_value()) {
                expect(eq(result->qname, host)) << wire;
                // The stream must resume just after the pointer for the blob to parse.
                expect(result->blob.qtype == DNSQueryType::A) << wire;
                expect(result->blob.qclass == DNSQueryClass::IN) << wire;
            }
        }
    } | std::vector<std::pair<std::string_view, std::vector<std::string_view>>> {
        // Pointer to a whole prior name.
        {"\007example\003com\0\x00\x01\x00\x01\xC0\x00\x00\x01\x00\x01"sv,
         {"example.com"sv, "example.com"sv}},
        // Prefix label followed by a pointer to a whole prior name.
        {"\007example\003com\0\x00\x01\x00\x01\004mail\xC0\x00\x00\x01\x00\x01"sv,
         {"example.com"sv, "mail.example.com"sv}},
        // Pointer into the middle of a prior name (suffix offset).
        {"\003www\007example\003com\0\x00\x01\x00\x01\004mail\xC0\x04\x00\x01\x00\x01"sv,
         {"www.example.com"sv, "mail.example.com"sv}},
        // Chain: prefix, pointer to a name that itself ends in a pointer.
        {"\007example\003com\0\x00\x01\x00\x01\003www\xC0\x00\x00\x01\x00\x01\004mail\xC0\x11\x00\x01\x00\x01"sv,
         {"example.com"sv, "www.example.com"sv, "mail.www.example.com"sv}},
    };

    "round trip query"_test = [](const auto& original_host) {
        fip::context ctx(true);
        DNSMessage message {ctx};
        message.add_question(original_host, DNSQueryType::A);
        std::array <char, 100> buf;
        std::ranges::fill(buf, 0xff);
        std::spanstream ss(buf);

        auto serialized = message.serialize(ss);
        expect(serialized.has_value());
        auto deserialized = DNSMessage::deserialize(ctx, ss);
        expect(deserialized.has_value());
        expect(eq(original_host, deserialized->get_questions().begin()->qname));
    } | std::vector<std::string_view> {
        "example.test.domain"sv,
        "averylonghostname.domain"sv,
        // The root name.
        ""sv,
    };

    "nasties not long enough"_test = [] (const auto& nasty) {
        fip::context ctx(true);
        std::array <char, 100> buf;
        std::ranges::fill(buf, 0xff);
        std::ranges::copy(nasty, buf.begin());
        auto span = std::span(buf.begin(), buf.begin() + nasty.size());
        std::ispanstream ss(span);

        jump_table_t jump_table;
        const auto result = DNSQuestion::deserialize(ctx, ss, jump_table);
        expect(eq(result.has_value(), false)) << nasty;
        if (!result.has_value()) {
            expect(eq(result.error().message(), magic_enum::enum_name(DNSError::DNSHostToHostPrematureEOF))) << nasty;
        }
    } | std::vector<std::string_view> {
        "\x14localhost\0\x00\x01\x00\x01"sv,
        "\077yo\003com\0\x00\x01\x00\x01"sv,
        "\x09x\x01c\0\x00\x01\x00\x01"sv,
        "\x0Fxxxxxxxxx\0\x00\x01\x00\x01"sv,
     };

    "nasties big segment"_test = [] (const auto& nastypair) {
        const auto &[nasty, len] = nastypair;
        fip::context ctx(true);
        std::ispanstream ss(nasty);

        jump_table_t jump_table;
        const auto result = DNSQuestion::deserialize(ctx, ss, jump_table);
        expect(eq(result.has_value(), false)) << nasty;
        expect(eq(result.error(), DNSError::DNSHostToHostExcessiveHostLabelSize)) << nasty;
    } | std::vector<std::pair<std::string_view, std::string_view>> {
        {"\x40x234567890123456789012345678901234567890123456789012345678901234\0"sv, "64"sv},
        {"\x41x123124312"sv, "65"sv},
        {"\x41x234567890123456789012345678901234567890123456789012345\003com"sv, "65"sv}
    };

    "question deserialize failure inputs"_test = [] (const auto &pair) {
        const auto& [fuzz, err] = pair;
        fip::context ctx(true);
        std::ispanstream ss(fuzz);

        jump_table_t jump_table;
        const auto result = DNSQuestion::deserialize(ctx, ss, jump_table);
        expect(!result.has_value())  << '"' << fuzz << '"';
        if (!result.has_value()) {
            expect(eq(result.error(), err)) << '"' << fuzz << '"';
        }
    } | std::vector<std::pair<std::string_view, DNSError>> {
        {"\x01\0\x00\x01\x00\x01"sv, DNSError::BlobifyStore},
        {"\xC0\x00\x00\x01\x00\x01"sv, DNSError::DNSHostToHostBadCompressionPointer},
        {"\xC0\x10\x00\x01\x00\x01"sv, DNSError::DNSHostToHostBadCompressionPointer},
        // Backward pointer into the middle of a label: byte 'a' reads as size 97.
        {"\004mail\xC0\x02\x00\x01\x00\x01"sv, DNSError::DNSHostToHostExcessiveHostLabelSize},
        // Backward pointer loop; the hostname size guard bounds it.
        {"\004mail\xC0\x00\x00\x01\x00\x01"sv, DNSError::DNSHostToHostExcessiveHostnameSize},
        {"\xC0"sv, DNSError::DNSHostToHostPrematureEOF},
        {"\x6Fx2345678901\003com\0\x00\x01\x00\x01"sv, DNSError::DNSHostToHostExcessiveHostLabelSize},
        {""sv, DNSError::DNSHostToHostPrematureEOF},
        {"\x01x\x00\x01\x00\x01"sv, DNSError::BlobifyStore},
        {"\x41\x00\x01\x00\x01"sv, DNSError::DNSHostToHostExcessiveHostLabelSize},
        {"\x7Fx3com\0\x00\x01\x00\x01"sv, DNSError::DNSHostToHostExcessiveHostLabelSize},
        {"\077x23456789012345678901234567890123456789012345678901234567890123\077y23456789012345678901234567890123456789012345678901234567890123\077z23456789012345678901234567890123456789012345678901234567890123\077a23456789012345678901234567890123456789012345678901234567890123\077b23456789012345678901234567890123456789012345678901234567890123\003com\x00\x01\x00\x01"sv, DNSError::DNSHostToHostExcessiveHostnameSize},
        {"\077x23456789012345678901234567890123456789012345678901234567890123\077y23456789012345678901234567890123456789012345678901234567890123\077z23456789012345678901234567890123456789012345678901234567890123\077h23456789012345678901234567890123456789012345678901234567890123\x01x\0\x00\x01\x00\x01"sv, DNSError::DNSHostToHostExcessiveHostnameSize},
        {"\077x23456789012345678901234567890123456789012345678901234567890123\077y23456789012345678901234567890123456789012345678901234567890123\077z23456789012345678901234567890123456789012345678901234567890123\077h23456789012345678901234567890123456789012345678901234567890123\x00\x01\x00\x01"sv, DNSError::DNSHostToHostExcessiveHostnameSize},
    };

    "question exceptional istream"_test = [] (const auto &fuzz) {
        fip::context ctx(true);
        std::ispanstream ss(fuzz);
        ss.exceptions(std::ispanstream::failbit | std::ispanstream::eofbit | std::ispanstream::badbit );

        jump_table_t jump_table;
        const auto result = DNSQuestion::deserialize(ctx, ss, jump_table);
        expect(!result.has_value());
        std::error_code code = result.error();
        expect(eq(code.category().name(), std::iostream_category().name()));
        expect(eq(static_cast<std::io_errc>(result.error().value()), std::io_errc::stream));
    } | std::vector {
        "9x"sv,
    };

    "question stream failure"_test = [] (const auto &pair) {
        auto& [in, failcount] = pair;
        fip::context ctx(true);
        throws_after_failcount_streambuf<1> sb(in, failcount);
        std::istream ss(&sb);

        jump_table_t jump_table;
        const auto result = DNSQuestion::deserialize(ctx, ss, jump_table);
        expect(!result.has_value());
        expect(eq(result.error(), DNSError::DeserializeUnexpectedException)) << '"' << in << '"';
    } | std::vector<std::pair<std::string_view, size_t>> {
        {"\013examplxxxxx\003com\0"sv, 1},
        {"\013axamplxxxxx\012emotionals\0"sv, 13},
    };

    "serialize"_test = [] (const auto &pair) {
        const auto &[host, dnshost] = pair;
        fip::context ctx{39, true};
        DNSMessage message {ctx};
        message.add_question(host, DNSQueryType::A);
        std::array <char, 100> buf;
        std::ranges::fill(buf, 0xff);
        std::ospanstream ss(buf);

        auto res = message.serialize(ss);
        expect(res.has_value()) << host;

        const auto header = message.get_header();
        expect(eq(std::string_view(ss.span()),
                  big_endian(header.id) + big_endian(std::to_underlying(header.flags)) + big_endian(header.qdcount)
                  + big_endian(header.ancount) + big_endian(header.nscount) + big_endian(header.arcount)
                  + std::string(dnshost) + big_endian(std::to_underlying(DNSQueryType::A)) + big_endian(std::to_underlying(DNSQueryClass::IN)))) << host;
    } | std::vector<std::pair<std::string_view, std::string_view>> {
        {"www.example.com"sv,                         "\x03www\007example\003com\0"sv},
        {"sub.domain.com"sv,                          "\003sub\006domain\003com\0"sv},
        {"localhost"sv,                               "\x09localhost\0"sv},
        {"api.ipify.org"sv,                           "\003api\005ipify\003org\0"sv},
        {"ifconfig.me"sv,                             "\x08ifconfig\002me\0"sv},
        {"icanhazip.com"sv,                           "\x09icanhazip\003com\0"sv},
        {"averylonghostname.com"sv,                   "\021averylonghostname\003com\0"sv},
        {"verylonghostname.averylonghostname.com"sv,  "\020verylonghostname\021averylonghostname\003com\0"sv},
        {"123.456.com"sv,                             "\003123\003456\003com\0"sv},
    };

    "serialize-deserialize"_test = [] (const auto &pair) {
        const auto &[host, dnshost] = pair;
        fip::context ctx{39, true};

        DNSMessage message {ctx};
        message.add_question(host, DNSQueryType::A);
        std::array <char, 100> buf;
        std::ranges::fill(buf, 0xff);
        std::spanstream ss(buf);

        auto res = message.serialize(ss);
        expect(res.has_value());
        auto query_out = DNSMessage::deserialize(ctx, ss);
        expect(query_out.has_value()) << host;

        if (query_out) {
            auto header_in = message.get_header();
            auto header_out = query_out->get_header();

            expect(eq(header_in.id, header_out.id));
            expect(eq(magic_enum::enum_flags_name(header_in.flags), magic_enum::enum_flags_name(header_out.flags)));
            expect(eq(header_in.ancount, header_out.ancount));
            expect(eq(header_in.nscount, header_out.nscount));
            expect(eq(header_in.arcount, header_out.arcount));
            expect(eq(header_in.qdcount, header_out.qdcount));

            auto question_in = *message.get_questions().begin();
            auto question_out = *query_out->get_questions().begin();

            expect(eq(question_out.qname, host));

            expect(eq(std::to_underlying(question_in.blob.qclass), std::to_underlying(question_out.blob.qclass)));
            expect(eq(std::to_underlying(question_in.blob.qtype), std::to_underlying(question_out.blob.qtype)));
            expect(eq(magic_enum::enum_name(question_in.blob.qclass), magic_enum::enum_name(question_out.blob.qclass)));
            expect(eq(magic_enum::enum_name(question_in.blob.qtype), magic_enum::enum_name(question_out.blob.qtype)));
        }
    } | std::vector<std::pair<std::string_view, std::string_view>> {
        {"www.example.com"sv,                         "\003www\007example\003com\0"sv},
        {"sub.domain.com"sv,                          "\003sub\006domain\003com\0"sv},
        {"localhost"sv,                               "\x09localhost\0"sv},
        {"api.ipify.org"sv,                           "\003api\005ipify\003org\0"sv},
        {"ifconfig.me"sv,                             "\x08ifconfig\002me\0"sv},
        {"icanhazip.com"sv,                           "\x09icanhazip\003com\0"sv},
        {"averylonghostname.com"sv,                   "\021averylonghostname\003com\0"sv},
        {"verylonghostname.averylonghostname.com"sv,  "\020verylonghostname\021averylonghostname\003com\0"sv},
    };

    "format"_test = [] {
        expect(eq("DNSHeaderFlags { QR: Query, Flags: Truncated|Authoritative, OpCode: SERVER_STATUS_REQUEST, ResponseCode: NAME_ERROR }"sv,
                  std::format("{}",
                              static_cast<DNSHeaderFlags>(Authoritative
                                                          | Truncated
                                                          | std::to_underlying(DNSResponseCodes::NAME_ERROR)
                                                          // RFC 1035 §4.1.1 puts OPCODE at bits 11-14; spelled out so the test doesn't trust opcode_shift.
                                                          | (static_cast<uint16_t>(std::to_underlying(DNSOpCodes::SERVER_STATUS_REQUEST)) << 11)))));
        expect(eq("DNSHeaderFlags { QR: Response, Flags: Authoritative, OpCode: STANDARD_QUERY, ResponseCode: NO_ERROR }"sv,
                  std::format("{}", static_cast<DNSHeaderFlags>(Authoritative | QueryResponse))));

        DNSHeader header { 0xee, DNSHeaderFlags::RecursionDesired, 1, 0, 0, 0 };
        expect(eq("DNSHeader { ID: 0xEE, DNSHeaderFlags { QR: Query, Flags: RecursionDesired, OpCode: STANDARD_QUERY, ResponseCode: NO_ERROR }, Questions: 1, Answers: 0, Authorities: 0, Additionals: 0 }"sv, std::format("{}", header)));

        // The octets are spelled out in wire order, not parsed by the library that formats them.
        RData_A a { {39, 139, 239, 39} };
        expect(eq("RData_A { ipv4_address: 39.139.239.39 }"sv, std::format("{}", a)));
        RData_AAAA aaaa { {0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa, 0xd8, 0x4d, 0x9f, 0x16, 0x28, 0x34, 0xb1} };
        expect(eq("RData_AAAA { ipv6_address: fe80::aad8:4d9f:1628:34b1 }"sv, std::format("{}", aaaa)));
    };

    "roundtrip message"_test = [] {
        fip::context ctx(39, true);
        std::array <char, 100> buf;
        std::spanstream ss(buf);
        std::ranges::fill(buf, 0x39);
        DNSMessage message {ctx};
        message.add_question("miku.cute", DNSQueryType::A);
        DNSResourceRecord answer = { "miku.cute", { DNSQueryType::A, DNSQueryClass::IN, 60, 4 }, RData_A { {39, 139, 239, 39} } };
        message.add_answer(answer);

        auto serialized = message.serialize(ss);
        expect(serialized.has_value());
        // The address reaches the wire in the order it prints.
        expect(std::string_view(ss.span()).ends_with("\47\213\357\47"sv));
        auto deserialized = DNSMessage::deserialize(ctx, ss);
        expect(deserialized.has_value());
        expect(eq("DNSMessage { DNSHeader { ID: 0x3596, DNSHeaderFlags { QR: Query, Flags: RecursionDesired, OpCode: STANDARD_QUERY, ResponseCode: NO_ERROR }, Questions: 1, Answers: 1, Authorities: 0, Additionals: 0 }, DNSQuestion { Name: miku.cute, Type: A, Class: IN }, DNSResourceRecord { Name: miku.cute, Type: A, Class: IN, TTL: 60, RDataLength: 4, RData_A { ipv4_address: 39.139.239.39 } } }"sv, std::format("{}", deserialized.value())));
    };

    static constexpr auto dig_write = "\314\347\1\0\0\1\0\0\0\0\0\1\4myip\7opendns\3com\0\0\1\0\1\0\0)\4\320\0\0\0\0\0\f\0\n\0\10\31\304\336\374/\340\7]"sv;

    "dig write"_test = [] {
        std::ispanstream ss {dig_write};
        fip::context ctx(39, true);
        ctx.log.set_verbose(true);

        auto message = DNSMessage::deserialize(ctx, ss);
        expect(message.has_value());
        if (message) {
            expect(eq("DNSMessage { DNSHeader { ID: 0xCCE7, DNSHeaderFlags { QR: Query, Flags: RecursionDesired, OpCode: STANDARD_QUERY, ResponseCode: NO_ERROR }, Questions: 1, Answers: 0, Authorities: 0, Additionals: 1 }, DNSQuestion { Name: myip.opendns.com, Type: A, Class: IN }, EDNS_ResourceRecord { Type: OPT, UDP_PayloadSize: 1232, ExtendedRCode: 0, Version: 0, Flags: 0x0000, RDataLength: 12, EDNS0_Option { OptionCode: COOKIE, OptionDataSize: 8, Data: { 0x19C4DEFC2FE0075D } } } }"sv, std::format("{}", *message)));
        } else {
            expect(eq("meow!"sv, message.error().message()));
        }

    };

    "dig write round trip"_test = [] {
        std::ispanstream in {dig_write};
        fip::context ctx(39, true);

        auto message = DNSMessage::deserialize(ctx, in);
        expect(fatal(message.has_value()));
        std::array<char, max_udp_message_octets> buf;
        std::ospanstream out {buf};
        expect(message->serialize(out).has_value());
        // The capture has no compression pointers, so its OPT record must come back octet for octet.
        expect(eq(dig_write, std::string_view(out.span())));
    };

    "dig read"_test = [] {
        constexpr auto buf = "\314\347\201\200\0\1\0\1\0\0\0\1\4myip\7opendns\3com\0\0\1\0\1\300\f\0\1\0\1\0\0\0\0\0\4HnPY\0\0)\20\0\0\0\0\0\0\0"sv;
        std::ispanstream ss {buf};
        fip::context ctx(39, true);
        ctx.log.set_verbose(true);

        auto message = DNSMessage::deserialize(ctx, ss);
        expect(message.has_value());
        if (message) {
            expect(eq("DNSMessage { DNSHeader { ID: 0xCCE7, DNSHeaderFlags { QR: Response, Flags: RecursionAvailable|RecursionDesired, OpCode: STANDARD_QUERY, ResponseCode: NO_ERROR }, Questions: 1, Answers: 1, Authorities: 0, Additionals: 1 }, DNSQuestion { Name: myip.opendns.com, Type: A, Class: IN }, DNSResourceRecord { Name: myip.opendns.com, Type: A, Class: IN, TTL: 0, RDataLength: 4, RData_A { ipv4_address: 72.110.80.89 } }, EDNS_ResourceRecord { Type: OPT, UDP_PayloadSize: 4096, ExtendedRCode: 0, Version: 0, Flags: 0x0000, RDataLength: 0 } }"sv, std::format("{}", *message)));
        } else {
            expect(eq("nyan!"sv, message.error().message()));
        }

    };

    // Real responses at the RFC 1035 limits, captured 2026-09-29 with
    // strace -e trace=recvmsg dig +noedns A <name>.
    static constexpr auto max_label_name = "thelongestdomainnameintheworldandthensomeandthensomemoreandmore.com"sv;
    static constexpr auto max_label_response = "\347\234\201\200\0\1\0\1\0\0\0\0?thelongestdomainnameintheworldandthensomeandthensomemoreandmore\3com\0\0\1\0\1\300\f\0\1\0\1\0\0\33i\0\4\37\301\200-"sv;
    static constexpr auto max_name_name = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.1-2-3-4-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.sslip.io"sv;
    static constexpr auto max_name_response = "\\&\201\200\0\1\0\1\0\0\0\0?aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa?aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa?aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa41-2-3-4-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\5sslip\2io\0\0\1\0\1\300\f\0\1\0\1\0\0\rZ\0\4\1\2\3\4"sv;

    "dig read at size limits"_test = [] (const auto& capture) {
        const auto& [name, buf, address] = capture;
        fip::context ctx(39, true);
        std::ispanstream ss {buf};

        auto message = DNSMessage::deserialize(ctx, ss);
        expect(message.has_value()) << name;
        if (message) {
            expect(eq(name, message->get_questions().front().qname));
            expect(eq(name, message->get_answers().front().name));
        }

        DNSResolver resolver {ctx};
        DNSMessage query {ctx};
        query.add_question(name, DNSQueryType::A);
        auto parsed = resolver.parse_dns_response(with_id(buf, query), query, fip::AddressFamily::V4);
        expect(parsed.has_value()) << name;
        if (parsed) {
            expect(eq(address, *parsed));
        }
    } | std::vector<std::tuple<std::string_view, std::string_view, std::string_view>> {
        {max_label_name, max_label_response, "31.193.128.45"sv},
        {max_name_name, max_name_response, "1.2.3.4"sv},
    };

    // A server can't send names past the limits, so these grow the real
    // captures by one byte.
    "dig read past size limits"_test = [] (const auto& mutation) {
        const auto& [capture, from, to, err] = mutation;
        std::string buf {capture};
        const auto anchor = std::ranges::search(buf, from);
        expect(fatal(!anchor.empty())) << from;
        buf.replace(anchor.begin(), anchor.end(), to);
        fip::context ctx(39, true);
        std::ispanstream ss {buf};

        auto message = DNSMessage::deserialize(ctx, ss);
        expect(!message.has_value());
        if (!message) {
            expect(eq(message.error(), err));
        }
    } | std::vector<std::tuple<std::string_view, std::string_view, std::string_view, DNSError>> {
        // 64-byte label.
        {max_label_response, "?the"sv, "@ethe"sv, DNSError::DNSHostToHostExcessiveHostLabelSize},
        // 256-octet question name.
        {max_name_response, "41-2-3-4-"sv, "5b1-2-3-4-"sv, DNSError::DNSHostToHostExcessiveHostnameSize},
        // Answer name of one label plus a pointer to the 255-octet question name.
        {max_name_response, "\300\f"sv, "\1x\300\f"sv, DNSError::DNSHostToHostExcessiveHostnameSize},
    };

    "serialize at size limits"_test = [] (const auto& name) {
        fip::context ctx(39, true);
        DNSMessage message {ctx};
        message.add_question(name, DNSQueryType::A);
        std::array<char, max_udp_message_octets> buf;
        std::spanstream ss(buf);

        expect(message.serialize(ss).has_value()) << name;
        auto deserialized = DNSMessage::deserialize(ctx, ss);
        expect(deserialized.has_value()) << name;
        if (deserialized) {
            expect(eq(name, deserialized->get_questions().front().qname));
        }
    } | std::vector {max_label_name, max_name_name};

    "serialize past size limits"_test = [] (const auto& mutation) {
        const auto& [name, err] = mutation;
        fip::context ctx(39, true);
        DNSMessage message {ctx};
        message.add_question(name, DNSQueryType::A);
        std::array<char, max_udp_message_octets> buf;
        std::ospanstream ss(buf);

        const auto serialized = message.serialize(ss);
        expect(!serialized.has_value()) << name;
        if (!serialized) {
            expect(eq(serialized.error(), err)) << name;
        }
    } | std::vector<std::pair<std::string, DNSError>> {
        // 64-byte label.
        {std::format("e{}", max_label_name), DNSError::HostToDNSHostExcessiveHostLabelSize},
        // 254 text characters, a 256-octet name.
        {std::format("{}x", max_name_name), DNSError::HostToDNSHostExcessiveHostnameSize},
    };

    "serialize unimplemented record types"_test = [] (const auto& unimplemented) {
        const auto& [type, rdata] = unimplemented;
        fip::context ctx(39, true);
        DNSResourceRecord record { "miku.cute", { type, DNSQueryClass::IN, 60, 0 }, rdata };
        std::array<char, 100> buf;
        std::ospanstream ss(buf);

        const auto serialized = record.serialize(ctx, ss);
        expect(!serialized.has_value()) << enum_name_or_value(type);
        if (!serialized) {
            expect(eq(serialized.error(), DNSError::SerializeUnimplementedType)) << enum_name_or_value(type);
        }
        // Refused before the name, so no header claims rdata that never follows.
        expect(ss.span().empty()) << enum_name_or_value(type);
    } | std::vector<std::pair<DNSQueryType, DNSResourceRecord::RDataVariant_t>> {
        {DNSQueryType::NS, RData_NS {"ns.miku.cute"}},
        {DNSQueryType::CNAME, RData_CNAME {"miku.cute"}},
        {DNSQueryType::MX, RData_MX {10, "mail.miku.cute"}},
        {DNSQueryType::SRV, RData_SRV {0, 0, 53, "miku.cute"}},
        // RRSIG, which deserialize skips.
        {static_cast<DNSQueryType>(46), RData_A {}},
    };

    "serialize txt string at size limit"_test = [] {
        fip::context ctx(39, true);
        // The limit is spelled out, not taken from the constant under test.
        const std::string longest(255, 'x');
        DNSMessage message {ctx};
        message.add_answer(DNSResourceRecord { "miku.cute", { DNSQueryType::TXT, DNSQueryClass::IN, 60, 256 }, RData_TXT { {longest} } });
        std::array<char, max_udp_message_octets> buf;
        std::spanstream ss(buf);

        expect(message.serialize(ss).has_value());
        auto deserialized = DNSMessage::deserialize(ctx, ss);
        expect(deserialized.has_value());
        if (deserialized) {
            expect(std::get<RData_TXT>(deserialized->get_answers().front().rdata).strings == std::vector {longest});
        }
    };

    "serialize txt string past size limit"_test = [] (const auto& strings) {
        fip::context ctx(39, true);
        DNSResourceRecord record { "miku.cute", { DNSQueryType::TXT, DNSQueryClass::IN, 60, 0 }, RData_TXT { strings } };
        std::array<char, max_udp_message_octets> buf;
        std::ospanstream ss(buf);

        const auto serialized = record.serialize(ctx, ss);
        expect(!serialized.has_value());
        if (!serialized) {
            expect(eq(serialized.error(), DNSError::SerializeExcessiveTextSize));
        }
        // Refused before the name, so not even the strings ahead of the long one reach the wire.
        expect(ss.span().empty());
    } | std::vector<std::vector<std::string>> {
        {std::string(256, 'x')},
        {"198.51.100.39"s, std::string(256, 'x')},
    };

    "record serialization short writes"_test = [] (const auto& record) {
        fip::context ctx(39, true);
        // Room for the name and header, but not for all of the rdata.
        std::array<char, 24> buf;
        std::ospanstream ss(buf);

        const auto serialized = record.serialize(ctx, ss);
        expect(!serialized.has_value()) << enum_name_or_value(record.blob.type);
        if (!serialized) {
            expect(eq(serialized.error(), DNSError::SerializeStreamFailure)) << enum_name_or_value(record.blob.type);
        }
    } | std::vector<DNSResourceRecord> {
        {"miku.cute", { DNSQueryType::A, DNSQueryClass::IN, 60, 4 }, RData_A {}},
        {"miku.cute", { DNSQueryType::AAAA, DNSQueryClass::IN, 60, 16 }, RData_AAAA {}},
        {"miku.cute", { DNSQueryType::TXT, DNSQueryClass::IN, 60, 14 }, RData_TXT { {"198.51.100.39"} }},
        {"", { DNSQueryType::OPT, static_cast<DNSQueryClass>(1232), 0, 20 }, RData_OPT { { DNSOption { { EDNSOptionCode::Padding, 16 }, std::vector<uint8_t>(16) } } }},
    };

    // Every record here declares the wrong lengths; the wire and the record read back from it must carry the rdata's own.
    "serialize derives lengths from the rdata"_test = [] (const auto& derived) {
        const auto& [record, wire, formatted] = derived;
        fip::context ctx(39, true);
        std::array<char, 100> buf;
        std::ospanstream out(buf);

        expect(record.serialize(ctx, out).has_value()) << formatted;
        expect(eq(wire, std::string_view(out.span()))) << formatted;

        std::ispanstream in {out.span()};
        jump_table_t jump_table;
        const auto deserialized = DNSResourceRecord::deserialize(ctx, in, jump_table);
        expect(fatal(deserialized.has_value())) << formatted;
        expect(eq(formatted, std::format("{}", *deserialized)));
        // RDLENGTH covered the rdata exactly, so the record read back ends where the wire does.
        expect(eq(in.peek(), std::ispanstream::traits_type::eof())) << formatted;
    } | std::vector<std::tuple<DNSResourceRecord, std::string_view, std::string_view>> {
        // Declares no rdata at all.
        {{"miku.cute", { DNSQueryType::A, DNSQueryClass::IN, 60, 0 }, RData_A { {39, 139, 239, 39} }},
         "\4miku\4cute\0\0\1\0\1\0\0\0<\0\4\47\213\357\47"sv,
         "DNSResourceRecord { Name: miku.cute, Type: A, Class: IN, TTL: 60, RDataLength: 4, RData_A { ipv4_address: 39.139.239.39 } }"sv},
        // Declares an A record's length.
        {{"miku.cute", { DNSQueryType::AAAA, DNSQueryClass::IN, 60, 4 }, RData_AAAA { {0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa, 0xd8, 0x4d, 0x9f, 0x16, 0x28, 0x34, 0xb1} }},
         "\4miku\4cute\0\0\34\0\1\0\0\0<\0\20\376\200\0\0\0\0\0\0\252\330\115\237\26\50\64\261"sv,
         "DNSResourceRecord { Name: miku.cute, Type: AAAA, Class: IN, TTL: 60, RDataLength: 16, RData_AAAA { ipv6_address: fe80::aad8:4d9f:1628:34b1 } }"sv},
        // Declares only the first string.
        {{"miku.cute", { DNSQueryType::TXT, DNSQueryClass::IN, 60, 14 }, RData_TXT { {"198.51.100.39", "second"} }},
         "\4miku\4cute\0\0\20\0\1\0\0\0<\0\25\015198.51.100.39\6second"sv,
         "DNSResourceRecord { Name: miku.cute, Type: TXT, Class: IN, TTL: 60, RDataLength: 21, RData_TXT: 198.51.100.39 second }"sv},
        // The dig write capture's OPT record, declaring the right RDLENGTH but more option data than there is.
        {{"", { DNSQueryType::OPT, static_cast<DNSQueryClass>(1232), 0, 12 }, RData_OPT { { DNSOption { { EDNSOptionCode::COOKIE, 39 }, {0x19, 0xc4, 0xde, 0xfc, 0x2f, 0xe0, 0x07, 0x5d} } } }},
         "\0\0)\4\320\0\0\0\0\0\f\0\n\0\10\31\304\336\374/\340\7]"sv,
         "EDNS_ResourceRecord { Type: OPT, UDP_PayloadSize: 1232, ExtendedRCode: 0, Version: 0, Flags: 0x0000, RDataLength: 12, EDNS0_Option { OptionCode: COOKIE, OptionDataSize: 8, Data: { 0x19C4DEFC2FE0075D } } }"sv},
        // An RDLENGTH that counts only the first option, and options declaring less and more data than they have.
        {{"", { DNSQueryType::OPT, static_cast<DNSQueryClass>(1232), 0, 12 }, RData_OPT { { DNSOption { { EDNSOptionCode::COOKIE, 0 }, {0x19, 0xc4, 0xde, 0xfc, 0x2f, 0xe0, 0x07, 0x5d} }, DNSOption { { EDNSOptionCode::Padding, 16 }, std::vector<uint8_t>(3) } } }},
         "\0\0)\4\320\0\0\0\0\0\23\0\n\0\10\31\304\336\374/\340\7]\0\f\0\3\0\0\0"sv,
         "EDNS_ResourceRecord { Type: OPT, UDP_PayloadSize: 1232, ExtendedRCode: 0, Version: 0, Flags: 0x0000, RDataLength: 19, EDNS0_Option { OptionCode: COOKIE, OptionDataSize: 8, Data: { 0x19C4DEFC2FE0075D } }, EDNS0_Option { OptionCode: Padding, OptionDataSize: 3, Data: { 0x000000 } } }"sv},
    };

    "serialize rdata at size limit"_test = [] (const auto& record) {
        fip::context ctx(39, true);
        std::stringstream ss;

        expect(record.serialize(ctx, ss).has_value()) << enum_name_or_value(record.blob.type);
        jump_table_t jump_table;
        const auto deserialized = DNSResourceRecord::deserialize(ctx, ss, jump_table);
        expect(fatal(deserialized.has_value())) << enum_name_or_value(record.blob.type);
        // The limit is spelled out, not taken from the constant under test.
        expect(eq(deserialized->blob.rdlength, 65535)) << enum_name_or_value(record.blob.type);
        // The declared lengths are the right ones here, so the record must come back whole.
        expect(std::format("{}", *deserialized) == std::format("{}", record)) << enum_name_or_value(record.blob.type);
    } | std::vector<DNSResourceRecord> {
        // 257 strings of 1 + 254 octets.
        {"miku.cute", { DNSQueryType::TXT, DNSQueryClass::IN, 60, 65535 }, RData_TXT { std::vector(257, std::string(254, 'x')) }},
        // One option of 4 + 65531 octets.
        {"", { DNSQueryType::OPT, static_cast<DNSQueryClass>(1232), 0, 65535 }, RData_OPT { { DNSOption { { EDNSOptionCode::Padding, 65531 }, std::vector<uint8_t>(65531) } } }},
    };

    "serialize rdata past size limit"_test = [] (const auto& record) {
        fip::context ctx(39, true);
        // Room for any record, so only the length check can refuse one.
        std::ostringstream ss;

        const auto serialized = record.serialize(ctx, ss);
        expect(!serialized.has_value()) << enum_name_or_value(record.blob.type);
        if (!serialized) {
            expect(eq(serialized.error(), DNSError::SerializeExcessiveRdataSize)) << enum_name_or_value(record.blob.type);
        }
        // Refused before the name, so no header claims a length the rdata does not have.
        expect(ss.view().empty()) << enum_name_or_value(record.blob.type);
    } | std::vector<DNSResourceRecord> {
        // 256 strings of 1 + 255 octets, one octet past the 65535 RDLENGTH holds.
        {"miku.cute", { DNSQueryType::TXT, DNSQueryClass::IN, 60, 0 }, RData_TXT { std::vector(256, std::string(255, 'x')) }},
        // One option of 4 + 65532 octets.
        {"", { DNSQueryType::OPT, static_cast<DNSQueryClass>(1232), 0, 0 }, RData_OPT { { DNSOption { { EDNSOptionCode::Padding, 0 }, std::vector<uint8_t>(65532) } } }},
        // An option whose data alone is too long for its OPTION-LENGTH.
        {"", { DNSQueryType::OPT, static_cast<DNSQueryClass>(1232), 0, 0 }, RData_OPT { { DNSOption { { EDNSOptionCode::Padding, 0 }, std::vector<uint8_t>(65536) } } }},
        // Two options of 4 + 32764 octets, each short enough alone.
        {"", { DNSQueryType::OPT, static_cast<DNSQueryClass>(1232), 0, 0 }, RData_OPT { { DNSOption { { EDNSOptionCode::Padding, 0 }, std::vector<uint8_t>(32764) }, DNSOption { { EDNSOptionCode::Padding, 0 }, std::vector<uint8_t>(32764) } } }},
    };

    "serialize opt rdata past size limit"_test = [] {
        fip::context ctx(39, true);
        // The first option fits; the second takes the rdata to 12 + 4 + 65520 octets, one past 65535.
        const RData_OPT opt { { DNSOption { { EDNSOptionCode::COOKIE, 8 }, std::vector<uint8_t>(8) }, DNSOption { { EDNSOptionCode::Padding, 0 }, std::vector<uint8_t>(65520) } } };
        std::ostringstream ss;

        const auto serialized = opt.serialize(ctx, ss);
        expect(!serialized.has_value());
        if (!serialized) {
            expect(eq(serialized.error(), DNSError::SerializeExcessiveRdataSize));
        }
        // Refused before the first option, so not even the one that fits reaches the wire.
        expect(ss.view().empty());
    };

    // blobify seeks only inside lens_load and lens_store, which fetchip does not call, so no deserialize path reaches these.
    "blob seek past the stream"_test = [] (const auto& seek) {
        const auto& [offset, load_error, store_error] = seek;
        std::array<char, 4> buf {};
        std::ispanstream is {buf};
        std::ospanstream os {buf};
        BlobLoader loader {is};
        BlobStorer storer {os};
        const auto thrown = [](auto&& f) -> std::error_code {
            try {
                f();
            } catch (const std::system_error& e) {
                return e.code();
            }
            return {};
        };

        expect(eq(thrown([&] { loader.seek(offset); }), load_error)) << offset;
        expect(eq(thrown([&] { storer.seek(offset); }), store_error)) << offset;
    } | std::vector<std::tuple<std::ptrdiff_t, std::error_code, std::error_code>> {
        {4, {}, {}},
        {5, make_error_code(DNSError::DeserializeStreamFailure), make_error_code(DNSError::SerializeStreamFailure)},
        {-1, make_error_code(DNSError::DeserializeStreamFailure), make_error_code(DNSError::SerializeStreamFailure)},
    };

    "edns nonzero ttl"_test = [] {
        constexpr auto buf = "\314\347\201\200\0\1\0\1\0\0\0\1\4myip\7opendns\3com\0\0\1\0\1\300\f\0\1\0\1\0\0\0\0\0\4HnPY\0\0)\20\0\1\0\200\0\0\0"sv;
        std::ispanstream ss {buf};
        fip::context ctx(39, true);
        ctx.log.set_verbose(true);

        auto message = DNSMessage::deserialize(ctx, ss);
        expect(message.has_value());
        if (message) {
            expect(eq("DNSMessage { DNSHeader { ID: 0xCCE7, DNSHeaderFlags { QR: Response, Flags: RecursionAvailable|RecursionDesired, OpCode: STANDARD_QUERY, ResponseCode: NO_ERROR }, Questions: 1, Answers: 1, Authorities: 0, Additionals: 1 }, DNSQuestion { Name: myip.opendns.com, Type: A, Class: IN }, DNSResourceRecord { Name: myip.opendns.com, Type: A, Class: IN, TTL: 0, RDataLength: 4, RData_A { ipv4_address: 72.110.80.89 } }, EDNS_ResourceRecord { Type: OPT, UDP_PayloadSize: 4096, ExtendedRCode: 1, Version: 0, Flags: DO, RDataLength: 0 } }"sv, std::format("{}", *message)));
        } else {
            expect(eq("nyan!"sv, message.error().message()));
        }
    };

    "edns unknown flags"_test = [] {
        constexpr auto buf = "\314\347\201\200\0\1\0\1\0\0\0\1\4myip\7opendns\3com\0\0\1\0\1\300\f\0\1\0\1\0\0\0\0\0\4HnPY\0\0)\20\0\0\1\100\0\0\0"sv;
        std::ispanstream ss {buf};
        fip::context ctx(39, true);
        ctx.log.set_verbose(true);

        auto message = DNSMessage::deserialize(ctx, ss);
        expect(message.has_value());
        if (message) {
            expect(eq("DNSMessage { DNSHeader { ID: 0xCCE7, DNSHeaderFlags { QR: Response, Flags: RecursionAvailable|RecursionDesired, OpCode: STANDARD_QUERY, ResponseCode: NO_ERROR }, Questions: 1, Answers: 1, Authorities: 0, Additionals: 1 }, DNSQuestion { Name: myip.opendns.com, Type: A, Class: IN }, DNSResourceRecord { Name: myip.opendns.com, Type: A, Class: IN, TTL: 0, RDataLength: 4, RData_A { ipv4_address: 72.110.80.89 } }, EDNS_ResourceRecord { Type: OPT, UDP_PayloadSize: 4096, ExtendedRCode: 0, Version: 1, Flags: 0x4000, RDataLength: 0 } }"sv, std::format("{}", *message)));
        } else {
            expect(eq("nyan!"sv, message.error().message()));
        }
    };

    "dig read txt"_test = [] {
        constexpr auto buf = "\314\347\204\0\0\1\0\1\0\0\0\0\3o-o\6myaddr\1l\6google\3com\0\0\20\0\1\300\14\0\20\0\1\0\0\0<\0\16\015198.51.100.39"sv;
        std::ispanstream ss {buf};
        fip::context ctx(39, true);
        ctx.log.set_verbose(true);

        auto message = DNSMessage::deserialize(ctx, ss);
        expect(message.has_value());
        if (message) {
            expect(eq("DNSMessage { DNSHeader { ID: 0xCCE7, DNSHeaderFlags { QR: Response, Flags: Authoritative, OpCode: STANDARD_QUERY, ResponseCode: NO_ERROR }, Questions: 1, Answers: 1, Authorities: 0, Additionals: 0 }, DNSQuestion { Name: o-o.myaddr.l.google.com, Type: TXT, Class: IN }, DNSResourceRecord { Name: o-o.myaddr.l.google.com, Type: TXT, Class: IN, TTL: 60, RDataLength: 14, RData_TXT: 198.51.100.39 } }"sv, std::format("{}", *message)));
        } else {
            expect(eq("nyan!"sv, message.error().message()));
        }
    };

    "txt multiple strings"_test = [] {
        constexpr auto buf = "\314\347\204\0\0\1\0\1\0\0\0\1\3o-o\6myaddr\1l\6google\3com\0\0\20\0\1\300\14\0\20\0\1\0\0\0<\0\25\015198.51.100.39\6second\0\0)\20\0\0\0\0\0\0\0"sv;
        std::ispanstream ss {buf};
        fip::context ctx(39, true);
        ctx.log.set_verbose(true);

        auto message = DNSMessage::deserialize(ctx, ss);
        expect(message.has_value());
        if (message) {
            expect(eq("DNSMessage { DNSHeader { ID: 0xCCE7, DNSHeaderFlags { QR: Response, Flags: Authoritative, OpCode: STANDARD_QUERY, ResponseCode: NO_ERROR }, Questions: 1, Answers: 1, Authorities: 0, Additionals: 1 }, DNSQuestion { Name: o-o.myaddr.l.google.com, Type: TXT, Class: IN }, DNSResourceRecord { Name: o-o.myaddr.l.google.com, Type: TXT, Class: IN, TTL: 60, RDataLength: 21, RData_TXT: 198.51.100.39 second }, EDNS_ResourceRecord { Type: OPT, UDP_PayloadSize: 4096, ExtendedRCode: 0, Version: 0, Flags: 0x0000, RDataLength: 0 } }"sv, std::format("{}", *message)));
        } else {
            expect(eq("nyan!"sv, message.error().message()));
        }
    };

    "rdlength failures"_test = [] (const auto& buf) {
        std::ispanstream ss {buf};
        fip::context ctx(39, true);

        auto message = DNSMessage::deserialize(ctx, ss);
        expect(eq(message.has_value(), false)) << buf;
        if (!message) {
            expect(eq(message.error(), DNSError::DeserializePrematureEOF)) << buf;
        }
    } | std::vector<std::string_view> {
        "\314\347\204\0\0\1\0\1\0\0\0\0\3o-o\6myaddr\1l\6google\3com\0\0\20\0\1\300\14\0\20\0\1\0\0\0<\0\16\017198.51.100.39"sv,
        "\314\347\204\0\0\1\0\1\0\0\0\0\3o-o\6myaddr\1l\6google\3com\0\0\20\0\1\300\14\0\20\0\1\0\0\0<\0\16\015198.51.100"sv,
        "\314\347\204\0\0\1\0\1\0\0\0\0\3o-o\6myaddr\1l\6google\3com\0\0\20\0\1\300\14\0\20\0\1\0\0\0<\0\0"sv,
        "\314\347\204\0\0\1\0\1\0\0\0\0\3o-o\6myaddr\1l\6google\3com\0\0\20\0\1\300\14\0\20\0\1\0\0\0<\0\16\2ns\015198.51.100"sv,
        "\314\347\204\0\0\1\0\1\0\0\0\0\3o-o\6myaddr\1l\6google\3com\0\0\20\0\1\300\14\0\5\0\1\0\0\0<\0\4\1x"sv,
        "\314\347\201\200\0\1\0\1\0\0\0\0\4myip\7opendns\3com\0\0\1\0\1\300\f\0\1\0\1\0\0\0\0\0\5HnPY!"sv,
        "\314\347\201\200\0\1\0\1\0\0\0\0\4myip\7opendns\3com\0\0\1\0\1\300\f\0\34\0\1\0\0\0\0\0\4HnPY"sv,
        "\314\347\201\200\0\1\0\1\0\0\0\0\4myip\7opendns\3com\0\0\1\0\1\300\f\0\34\0\1\0\0\0\0\0\0210123456789abcdefg"sv,
        "\314\347\201\200\0\1\0\1\0\0\0\0\4myip\7opendns\3com\0\0\1\0\1\300\f\0\34\0\1\0\0\0\0\0\20HnPY"sv,
        // OPT option claiming 8 data bytes with only 4 left in the message.
        "\314\347\1\0\0\1\0\0\0\0\0\1\4myip\7opendns\3com\0\0\1\0\1\0\0)\4\320\0\0\0\0\0\f\0\n\0\10\31\304\336\374"sv,
        // OPT option claiming 8 data bytes with only 7 left in an rdlength of 11.
        "\314\347\1\0\0\1\0\0\0\0\0\1\4myip\7opendns\3com\0\0\1\0\1\0\0)\4\320\0\0\0\0\0\13\0\n\0\10\31\304\336\374/\340u\35"sv,
        // OPT option header straddling an rdlength of 2.
        "\314\347\1\0\0\1\0\0\0\0\0\1\4myip\7opendns\3com\0\0\1\0\1\0\0)\4\320\0\0\0\0\0\2\0\n\0\10\31\304\336\374/\340u\35"sv,
        // A record claiming 4 rdata bytes with only 3 left in the message.
        "\314\347\201\200\0\1\0\1\0\0\0\0\4myip\7opendns\3com\0\0\1\0\1\300\f\0\1\0\1\0\0\0\0\0\4HnP"sv,
        // RRSIG claiming 8 rdata bytes with only 3 left in the message.
        "\314\347\201\200\0\1\0\1\0\0\0\0\4myip\7opendns\3com\0\0\1\0\1\300\f\0\56\0\1\0\0\0\0\0\10abc"sv,
    };

    "exception log names the catching function"_test = [] {
        std::ispanstream ss {"\314\347\201"sv};
        fip::context ctx(39, true);
        std::vector<std::string> printed;
        ctx.log.hook_print = [&](const std::string_view& msg) { printed.emplace_back(msg); };

        auto message = DNSMessage::deserialize(ctx, ss);
        expect(eq(message.has_value(), false));
        expect(std::ranges::any_of(printed, [](const std::string& line) {
            return line.contains("system_error exception!") && line.contains("DNSMessage::deserialize");
        })) << std::format("{}", printed);
    };

    "skip unknown record types"_test = [] {
        constexpr auto buf = "\314\347\201\200\0\1\0\2\0\0\0\1\4myip\7opendns\3com\0\0\1\0\1\300\f\0\56\0\1\0\0\0\0\0\3abc\300\f\0\1\0\1\0\0\0\0\0\4HnPY\300\f\0\101\0\1\0\0\0\0\0\2xy"sv;
        fip::context ctx(39, true);
        std::ispanstream ss {buf};

        auto message = DNSMessage::deserialize(ctx, ss);
        expect(message.has_value());
        if (message) {
            expect(eq("DNSMessage { DNSHeader { ID: 0xCCE7, DNSHeaderFlags { QR: Response, Flags: RecursionAvailable|RecursionDesired, OpCode: STANDARD_QUERY, ResponseCode: NO_ERROR }, Questions: 1, Answers: 2, Authorities: 0, Additionals: 1 }, DNSQuestion { Name: myip.opendns.com, Type: A, Class: IN }, DNSResourceRecord { Name: myip.opendns.com, Type: 46, Class: IN, TTL: 0, RDataLength: 3, (unimplemented rdata formatter) }, DNSResourceRecord { Name: myip.opendns.com, Type: A, Class: IN, TTL: 0, RDataLength: 4, RData_A { ipv4_address: 72.110.80.89 } }, DNSResourceRecord { Name: myip.opendns.com, Type: 65, Class: IN, TTL: 0, RDataLength: 2, (unimplemented rdata formatter) } }"sv, std::format("{}", *message)));
        }

        DNSResolver resolver {ctx};
        DNSMessage query {ctx};
        query.add_question("myip.opendns.com", DNSQueryType::A);
        auto address = resolver.parse_dns_response(with_id(buf, query), query, fip::AddressFamily::V4);
        expect(address.has_value());
        if (address) {
            expect(eq("72.110.80.89"sv, *address));
        }
    };

    "keep unknown edns options"_test = [] {
        constexpr auto buf = "\314\347\201\200\0\1\0\1\0\0\0\1\4myip\7opendns\3com\0\0\1\0\1\300\f\0\1\0\1\0\0\0\0\0\4HnPY\0\0)\20\0\0\0\0\0\0\10OD\0\4\1\2\3\4"sv;
        fip::context ctx(39, true);
        std::ispanstream ss {buf};

        auto message = DNSMessage::deserialize(ctx, ss);
        expect(message.has_value());
        if (message) {
            expect(eq("DNSMessage { DNSHeader { ID: 0xCCE7, DNSHeaderFlags { QR: Response, Flags: RecursionAvailable|RecursionDesired, OpCode: STANDARD_QUERY, ResponseCode: NO_ERROR }, Questions: 1, Answers: 1, Authorities: 0, Additionals: 1 }, DNSQuestion { Name: myip.opendns.com, Type: A, Class: IN }, DNSResourceRecord { Name: myip.opendns.com, Type: A, Class: IN, TTL: 0, RDataLength: 4, RData_A { ipv4_address: 72.110.80.89 } }, EDNS_ResourceRecord { Type: OPT, UDP_PayloadSize: 4096, ExtendedRCode: 0, Version: 0, Flags: 0x0000, RDataLength: 8, EDNS0_Option { OptionCode: 20292, OptionDataSize: 4, Data: { 0x01020304 } } } }"sv, std::format("{}", *message)));
        }
    };

    "address family of text"_test = [] {
        const auto cases = std::to_array<std::pair<std::string_view, std::optional<fip::AddressFamily>>>({
            {"198.51.100.39"sv, fip::AddressFamily::V4},
            {"2001:db8::39"sv, fip::AddressFamily::V6},
            {"::ffff:198.51.100.39"sv, fip::AddressFamily::V6},
            {"Query A or AAAA for your source address as seen by the resolver"sv, std::nullopt},
            {"\"198.51.100.39\""sv, std::nullopt},
            {"198.51.100.39\n"sv, std::nullopt},
            {""sv, std::nullopt},
        });
        for (const auto& [text, family] : cases) {
            expect(address_family_of(text) == family) << text;
        }
    };

    "parse tagged txt answer"_test = [] {
        constexpr auto tagged = "\314\347\204\0\0\1\0\1\0\0\0\0\6whoami\2ds\7akahelp\3net\0\0\20\0\1\300\14\0\20\0\1\0\0\0<\0\21\2ns\015198.51.100.39"sv;
        constexpr auto untagged = "\314\347\204\0\0\1\0\1\0\0\0\0\6whoami\2ds\7akahelp\3net\0\0\20\0\1\300\14\0\20\0\1\0\0\0<\0\10\2ns\4none"sv;
        fip::context ctx(39, true);
        DNSResolver resolver {ctx};
        DNSMessage query {ctx};
        query.add_question("whoami.ds.akahelp.net", DNSQueryType::TXT);

        auto address = resolver.parse_dns_response(with_id(tagged, query), query, fip::AddressFamily::V4);
        expect(address.has_value());
        if (address) {
            expect(eq("198.51.100.39"sv, *address));
        }
        expect(resolver.parse_dns_response(with_id(tagged, query), query, fip::AddressFamily::V6) == std::unexpected(make_error_code(DNSError::DNSResolverWrongFamily)));
        expect(resolver.parse_dns_response(with_id(untagged, query), query, fip::AddressFamily::V4) == std::unexpected(make_error_code(DNSError::DNSResolverUnexpectedAnswer)));
    };

    "parse answer after cname"_test = [] {
        constexpr auto buf = "\314\347\204\0\0\1\0\2\0\0\0\0\3o-o\6myaddr\1l\6google\3com\0\0\20\0\1\300\14\0\5\0\1\0\0\0<\0\4\1x\300\14\300\14\0\20\0\1\0\0\0<\0\16\015198.51.100.39"sv;
        constexpr auto cname_only = "\314\347\204\0\0\1\0\1\0\0\0\0\3o-o\6myaddr\1l\6google\3com\0\0\20\0\1\300\14\0\5\0\1\0\0\0<\0\4\1x\300\14"sv;
        fip::context ctx(39, true);
        DNSResolver resolver {ctx};
        DNSMessage query {ctx};
        query.add_question("o-o.myaddr.l.google.com", DNSQueryType::TXT);

        auto address = resolver.parse_dns_response(with_id(buf, query), query, fip::AddressFamily::V4);
        expect(address.has_value());
        if (address) {
            expect(eq("198.51.100.39"sv, *address));
        }
        expect(resolver.parse_dns_response(with_id(cname_only, query), query, fip::AddressFamily::V4) == std::unexpected(make_error_code(DNSError::DNSResolverUnexpectedAnswer)));
    };

    "reject mismatched response"_test = [] {
        constexpr auto response = "\314\347\204\0\0\1\0\1\0\0\0\0\6whoami\2ds\7akahelp\3net\0\0\20\0\1\300\14\0\20\0\1\0\0\0<\0\21\2ns\015198.51.100.39"sv;
        constexpr auto not_a_response = "\314\347\1\0\0\1\0\0\0\0\0\1\4myip\7opendns\3com\0\0\1\0\1\0\0)\4\320\0\0\0\0\0\f\0\n\0\10\31\304\336\374/\340\7]"sv;
        const auto mismatched = std::unexpected(make_error_code(DNSError::DNSResolverMismatchedResponse));
        fip::context ctx(39, true);
        DNSResolver resolver {ctx};

        DNSMessage query {ctx};
        query.add_question("whoami.ds.akahelp.net", DNSQueryType::TXT);
        const auto other_id = static_cast<uint16_t>(~query.get_header().id);
        expect(resolver.parse_dns_response(with_id(response, other_id), query, fip::AddressFamily::V4) == mismatched);

        DNSMessage other_name {ctx};
        other_name.add_question("whoami.ds.akahelp.org", DNSQueryType::TXT);
        expect(resolver.parse_dns_response(with_id(response, other_name), other_name, fip::AddressFamily::V4) == mismatched);

        DNSMessage other_type {ctx};
        other_type.add_question("whoami.ds.akahelp.net", DNSQueryType::A);
        expect(resolver.parse_dns_response(with_id(response, other_type), other_type, fip::AddressFamily::V4) == mismatched);

        DNSMessage a_query {ctx};
        a_query.add_question("myip.opendns.com", DNSQueryType::A);
        expect(resolver.parse_dns_response(with_id(not_a_response, a_query), a_query, fip::AddressFamily::V4) == mismatched);

        DNSMessage other_case {ctx};
        other_case.add_question("WhoAmI.DS.akahelp.net", DNSQueryType::TXT);
        auto address = resolver.parse_dns_response(with_id(response, other_case), other_case, fip::AddressFamily::V4);
        expect(address.has_value());
        if (address) {
            expect(eq("198.51.100.39"sv, *address));
        }
    };

    "query answers family"_test = [] {
        using enum DNSQueryType;
        using fip::AddressFamily;
        expect(query_answers_family(A, AddressFamily::Any));
        expect(query_answers_family(A, AddressFamily::V4));
        expect(!query_answers_family(A, AddressFamily::V6));
        expect(query_answers_family(AAAA, AddressFamily::Any));
        expect(!query_answers_family(AAAA, AddressFamily::V4));
        expect(query_answers_family(AAAA, AddressFamily::V6));
        expect(query_answers_family(TXT, AddressFamily::Any));
        expect(query_answers_family(TXT, AddressFamily::V4));
        expect(query_answers_family(TXT, AddressFamily::V6));
        expect(!query_answers_family(CNAME, AddressFamily::V4));
    };
}
