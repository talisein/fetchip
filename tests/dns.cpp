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

template<size_t fail_count>
class throws_after_failcount_streambuf : public std::basic_streambuf<char> {
public:
    std::string str;
    const char *begin;
    const char *it;
    const char *end;
    size_t count;
    size_t local_fail_count;
    throws_after_failcount_streambuf(size_t local_fail_count = fail_count) :
        std::basic_streambuf<char>(),
        count(0),
        local_fail_count(local_fail_count)
    {
    }

    throws_after_failcount_streambuf(std::string_view in, size_t local_fail_count = fail_count) :
        std::basic_streambuf<char>(),
        str(in),
        begin(std::to_address(in.begin())),
        it(begin),
        end(std::to_address(in.end())),
        count(0),
        local_fail_count(local_fail_count)
    {
    }

    virtual std::basic_streambuf<char>::int_type uflow() override {
        if (local_fail_count < count++) throw std::runtime_error("mock stream failure");
        if (it == end) return std::basic_streambuf<char>::traits_type::eof();
        auto ch = *it++;
        return ch;
    }

    virtual std::basic_streambuf<char>::int_type underflow() override {
        if (local_fail_count < count) throw std::runtime_error("mock stream failure");
        if (it == end) return std::basic_streambuf<char>::traits_type::eof();
        return *it;
    }

    virtual int_type overflow( int_type ch  ) override {
        if (local_fail_count < count++) {
            throw std::runtime_error("overflow");
        }
        return 1;
    }
};

template <typename CharT>
class e_failing_istringstream : public std::basic_istringstream<CharT> {
    public:
    template <typename T>
    e_failing_istringstream(T&& sv) : std::basic_istringstream<CharT>(std::forward<T>(sv)) {}
    std::istringstream::int_type get() {
        auto ch = std::istringstream::get();  // Get the next character from the stream
        if (ch == 'e') {
            this->setstate(std::ios_base::failbit);  // Set the failbit if 'e' is encountered
        }
        return ch;
    }

    e_failing_istringstream& operator>>( std::basic_streambuf<CharT, typename std::basic_istringstream<CharT>::traits_type>* sb ) {

        return *this;
    }
};


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
                expect(eq(std::string_view(buf.cbegin(),
                                           static_cast<std::streamoff>(ss.tellp()) - sizeof(DNSQuestionBlob)),
                          dnshost)) << host;
                DNSQuestionBlob blob;
                memcpy(&blob, buf.cbegin() + dnshost.size(), sizeof(DNSQuestionBlob));
                expect(eq(std::to_underlying(blob.qtype), std::byteswap(std::to_underlying(qtype))));
                expect(eq(std::to_underlying(blob.qclass), std::byteswap(std::to_underlying(qclass))));
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
        expect(eq(magic_enum::enum_name(static_cast<DNSError>(result.error().value())), magic_enum::enum_name(error)));
    } | std::vector<std::pair<std::string_view, DNSError>> {
        {"10tenletters10tenletters10tenletters3com"sv, DNSError::HostToDNSHostStreamFailure},
    };

    "question serialization exception"_test = [] (const auto &in) {
        const auto &[host, error] = in;
        fip::context ctx{39, true};
        DNSQuestion question { std::string(host), { DNSQueryType::A, DNSQueryClass::IN } };
        std::array <char, 20> buf;
        std::ranges::fill(buf, 0xff);
        std::ospanstream ss(buf);
        ss.exceptions(std::ios_base::badbit | std::ios_base::failbit);

        auto result = question.serialize(ctx, ss);
        expect(!result.has_value());
        expect(eq(magic_enum::enum_name(static_cast<DNSError>(result.error().value())), magic_enum::enum_name(error)));
    } | std::vector<std::pair<std::string_view, DNSError>> {
        {"\x0Atenletters\x0Atenletters\x0Atenletters\003com"sv, DNSError::HostToDNSHostStreamUnexpectedException},
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
        expect(eq(magic_enum::enum_name(static_cast<DNSError>(result.error().value())), magic_enum::enum_name(error)));
    } | std::vector<std::pair<std::string_view, DNSError>> {
        {"\x0Atenletters\x0Atenletters\x0Atenletters\003com"sv, DNSError::SerializeStreamFailure},
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
        expect(eq(magic_enum::enum_name(static_cast<DNSError>(result.error().value())), magic_enum::enum_name(error)));
    } | std::vector<std::pair<std::string_view, DNSError>> {
        {"\x0Atenletters\x0Atenletters\x0Atenletters\003com"sv, DNSError::SerializeUnexpectedException},
    };


    "question deserialize"_test = [] (const auto &pair){
        const auto &[dnshost, host] = pair;
        fip::context ctx(39, true);
        //ctx.log.set_verbose(true);
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
        {"\077x23456789012345678901234567890123456789012345678901234567890123\077y23456789012345678901234567890123456789012345678901234567890123\077z23456789012345678901234567890123456789012345678901234567890123\077a23456789012345678901234567890123456789012345678901234567890123\0\x00\x01\x00\x01"sv,
         "x23456789012345678901234567890123456789012345678901234567890123.y23456789012345678901234567890123456789012345678901234567890123.z23456789012345678901234567890123456789012345678901234567890123.a23456789012345678901234567890123456789012345678901234567890123"sv}
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
    };

    "nasties not long enough"_test = [] (const auto& nasty) {
        fip::context ctx(true);
        //ctx.log.set_verbose(true);
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
            expect(eq(magic_enum::enum_name(static_cast<DNSError>(result.error().value())), magic_enum::enum_name(err))) << '"' << fuzz << '"';
        }
    } | std::vector<std::pair<std::string_view, DNSError>> {
//        {"0\0\x00\x01\x00\x01"sv, DNSError::DNSHostToHostZeroHostLabelSize},
        {"\x01\0\x00\x01\x00\x01"sv, DNSError::BlobifyStore},
        {"\x6Fx2345678901\003com\0\x00\x01\x00\x01"sv, DNSError::DNSHostToHostExcessiveHostLabelSize},
//        {"1\x00\x01\x00\x01"sv, DNSError::DNSHostToHostNonnumericLabelSize},
        {""sv, DNSError::DNSHostToHostPrematureEOF},
//        {"\0\x00\x01\x00\x01"sv, DNSError::DNSHostToHostNullHostname},
        {"\x01x\x00\x01\x00\x01"sv, DNSError::BlobifyStore},
        {"\x41\x00\x01\x00\x01"sv, DNSError::DNSHostToHostExcessiveHostLabelSize},
        {"\xFFx3com\0\x00\x01\x00\x01"sv, DNSError::DNSHostToHostExcessiveHostLabelSize},
//        {"-1x3com\0\x00\x01\x00\x01"sv, DNSError::DNSHostToHostNonnumericLabelSize},
//        {"abcx3com\0\x00\x01\x00\x01"sv, DNSError::DNSHostToHostNonnumericLabelSize},
//        {"0x3com\0\x00\x01\x00\x01"sv, DNSError::DNSHostToHostZeroHostLabelSize},
        {"\077x23456789012345678901234567890123456789012345678901234567890123\077y23456789012345678901234567890123456789012345678901234567890123\077z23456789012345678901234567890123456789012345678901234567890123\077a23456789012345678901234567890123456789012345678901234567890123\077b23456789012345678901234567890123456789012345678901234567890123\003com\x00\x01\x00\x01"sv, DNSError::DNSHostToHostExcessiveHostnameSize},
        {"\077x23456789012345678901234567890123456789012345678901234567890123\077y23456789012345678901234567890123456789012345678901234567890123\077z23456789012345678901234567890123456789012345678901234567890123\077h23456789012345678901234567890123456789012345678901234567890123\x01x\0\x00\x01\x00\x01"sv, DNSError::DNSHostToHostExcessiveHostnameSize},
        {"\077x23456789012345678901234567890123456789012345678901234567890123\077y23456789012345678901234567890123456789012345678901234567890123\077z23456789012345678901234567890123456789012345678901234567890123\077h23456789012345678901234567890123456789012345678901234567890123\x00\x01\x00\x01"sv, DNSError::BlobifyStore},
    };

    "question exceptional istream"_test = [] (const auto &fuzz) {
        fip::context ctx(true);
        //ctx.log.set_verbose(true);
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
        //ctx.log.set_verbose(true);
        throws_after_failcount_streambuf<1> sb(in, failcount);
        std::istream ss(&sb);

        jump_table_t jump_table;
        const auto result = DNSQuestion::deserialize(ctx, ss, jump_table);
        expect(!result.has_value());
        expect(eq(magic_enum::enum_name(static_cast<DNSError>(result.error().value())), magic_enum::enum_name(DNSError::DeserializeUnexpectedException))) << '"' << in << '"';
    } | std::vector<std::pair<std::string_view, size_t>> {
        {"\013examplxxxxx\003com\0"sv, 1},
        {"\013axamplxxxxx\012emotionals\0"sv, 13},
    };

    "serialize"_test = [] (const auto &pair) {
        const auto &[host, dnshost] = pair;
        fip::context ctx{39, true};
        //ctx.log.set_verbose(true);
        DNSMessage message {ctx};
        message.add_question(host, DNSQueryType::A);
        std::array <char, 100> buf;
        std::ranges::fill(buf, 0xff);
        std::ospanstream ss(buf);

        [[maybe_unused]] auto res = message.serialize(ss);

        DNSHeader header_out;
        DNSQuestion question_out;
        std::memcpy(&header_out, buf.begin(), sizeof(DNSHeader));
        std::memcpy(&question_out.blob, buf.begin() + sizeof(DNSHeader) + dnshost.size(), sizeof(DNSQuestionBlob));

        expect(eq(header_out.id, std::byteswap(message.get_header().id)));
        expect(eq(std::to_underlying(header_out.flags), std::byteswap(std::to_underlying(message.get_header().flags))));
        expect(eq(header_out.ancount, std::byteswap(message.get_header().ancount)));
        expect(eq(header_out.nscount, std::byteswap(message.get_header().nscount)));
        expect(eq(header_out.arcount, std::byteswap(message.get_header().arcount)));
        expect(eq(header_out.qdcount, std::byteswap(message.get_header().qdcount)));
        expect(eq(header_out.id, htons(message.get_header().id)));
        expect(eq(std::to_underlying(header_out.flags), htons(std::to_underlying(message.get_header().flags))));
        expect(eq(header_out.ancount, htons(message.get_header().ancount)));
        expect(eq(header_out.nscount, htons(message.get_header().nscount)));
        expect(eq(header_out.arcount, htons(message.get_header().arcount)));
        expect(eq(header_out.qdcount, htons(message.get_header().qdcount)));

        expect(eq(std::string_view(buf.begin() + sizeof(DNSHeader), dnshost.size()), dnshost));

        expect(eq(std::to_underlying(question_out.blob.qclass), std::byteswap(std::to_underlying(message.get_questions().begin()->blob.qclass))));
        expect(eq(std::to_underlying(question_out.blob.qtype), std::byteswap(std::to_underlying(message.get_questions().begin()->blob.qtype))));
        expect(eq(std::to_underlying(question_out.blob.qclass), htons(std::to_underlying(message.get_questions().begin()->blob.qclass))));
        expect(eq(std::to_underlying(question_out.blob.qtype), htons(std::to_underlying(message.get_questions().begin()->blob.qtype))));


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
        //ctx.log.set_verbose(true);

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
                                                          | (static_cast<uint16_t>(std::to_underlying(DNSOpCodes::SERVER_STATUS_REQUEST)) << 11)))));
        expect(eq("DNSHeaderFlags { QR: Response, Flags: Authoritative, OpCode: STANDARD_QUERY, ResponseCode: NO_ERROR }"sv,
                  std::format("{}", static_cast<DNSHeaderFlags>(Authoritative | QueryResponse))));

        DNSHeader header { 0xee, DNSHeaderFlags::RecursionDesired, 1, 0, 0, 0 };
        expect(eq("DNSHeader { ID: 0xEE, DNSHeaderFlags { QR: Query, Flags: RecursionDesired, OpCode: STANDARD_QUERY, ResponseCode: NO_ERROR }, Questions: 1, Answers: 0, Authorities: 0, Additionals: 0 }"sv, std::format("{}", header)));

        RData_A a {};
        inet_pton(AF_INET, "39.139.239.39", &a.ipv4_address);
        if constexpr (std::endian::native != std::endian::big) {
            a.ipv4_address.s_addr = std::byteswap(a.ipv4_address.s_addr);
        }
        expect(eq("RData_A { ipv4_address: 39.139.239.39 }"sv, std::format("{}", a)));
        RData_AAAA aaaa {};
        inet_pton(AF_INET6, "fe80::aad8:4d9f:1628:34b1", &aaaa.ipv6_address);
        expect(eq("RData_AAAA { ipv6_address: fe80::aad8:4d9f:1628:34b1 }"sv, std::format("{}", aaaa)));

        fip::context ctx(39, true);
        DNSMessage message(ctx);
        message.add_question("yahoo.com", DNSQueryType::A);
        DNSResourceRecord answer;
        answer.name = "yahoo.com";
        answer.blob.query_class = DNSQueryClass::IN;
        answer.blob.type = DNSQueryType::A;
        answer.blob.rdlength = sizeof(RData_A);
        answer.blob.ttl = 60;
        answer.rdata = a;
        message.add_answer(answer);
        answer.blob.type = DNSQueryType::AAAA;
        answer.rdata = aaaa;
        message.add_answer(answer);

//        expect(eq(""sv, std::format("{}", message)));
    };

    "roundtrip message"_test = [] {
        fip::context ctx(39, true);
        std::array <char, 100> buf;
        std::spanstream ss(buf);
        std::ranges::fill(buf, 0x39);
        DNSMessage message {ctx};
        message.add_question("miku.cute", DNSQueryType::A);
        DNSResourceRecord answer = { "miku.cute", { DNSQueryType::A, DNSQueryClass::IN, 60, sizeof(RData_A) }, RData_A { in_addr {0x27272727} } };
        message.add_answer(answer);

        auto serialized = message.serialize(ss);
        expect(serialized.has_value());
        auto deserialized = DNSMessage::deserialize(ctx, ss);
        expect(deserialized.has_value());
        expect(eq("DNSMessage { DNSHeader { ID: 0x3596, DNSHeaderFlags { QR: Query, Flags: RecursionDesired, OpCode: STANDARD_QUERY, ResponseCode: NO_ERROR }, Questions: 1, Answers: 1, Authorities: 0, Additionals: 0 }, DNSQuestion { Name: miku.cute, Type: A, Class: IN }, DNSResourceRecord { Name: miku.cute, Type: A, Class: IN, TTL: 60, RDataLength: 4, RData_A { ipv4_address: 39.39.39.39 } } }"sv, std::format("{}", deserialized.value())));
    };

    "dig write"_test = [] {
        constexpr auto buf ="\314\347\1\0\0\1\0\0\0\0\0\1\4myip\7opendns\3com\0\0\1\0\1\0\0)\4\320\0\0\0\0\0\f\0\n\0\10\31\304\336\374/\340\7]"sv;
        std::ispanstream ss {buf};
        fip::context ctx(39, true);
        ctx.log.set_verbose(true);

        auto message = DNSMessage::deserialize(ctx, ss);
        expect(message.has_value());
        if (message) {
            expect(eq("DNSMessage { DNSHeader { ID: 0xCCE7, DNSHeaderFlags { QR: Query, Flags: RecursionDesired, OpCode: STANDARD_QUERY, ResponseCode: NO_ERROR }, Questions: 1, Answers: 0, Authorities: 0, Additionals: 1 }, DNSQuestion { Name: myip.opendns.com, Type: A, Class: IN }, EDNS_ResourceRecord { Type: OPT, UDP_PayloadSize: 1232, ExtendedRCode: 0, Version: 0, Flags: DO, RDataLength: 12, EDNS0_Option { OptionCode: COOKIE, OptionDataSize: 8, Data: { 0x19C4DEFC2FE075D } } } }"sv, std::format("{}", *message)));
        } else {
            expect(eq("meow!"sv, message.error().message()));
        }

    };

    "dig read"_test = [] {
        constexpr auto buf = "\314\347\201\200\0\1\0\1\0\0\0\1\4myip\7opendns\3com\0\0\1\0\1\300\f\0\1\0\1\0\0\0\0\0\4HnPY\0\0)\20\0\0\0\0\0\0\0"sv;
        std::ispanstream ss {buf};
        fip::context ctx(39, true);
        ctx.log.set_verbose(true);

        auto message = DNSMessage::deserialize(ctx, ss);
        expect(message.has_value());
        if (message) {
            expect(eq("DNSMessage { DNSHeader { ID: 0xCCE7, DNSHeaderFlags { QR: Response, Flags: RecursionAvailable|RecursionDesired, OpCode: STANDARD_QUERY, ResponseCode: NO_ERROR }, Questions: 1, Answers: 1, Authorities: 0, Additionals: 1 }, DNSQuestion { Name: myip.opendns.com, Type: A, Class: IN }, DNSResourceRecord { Name: myip.opendns.com, Type: A, Class: IN, TTL: 0, RDataLength: 4, RData_A { ipv4_address: 72.110.80.89 } }, EDNS_ResourceRecord { Type: OPT, UDP_PayloadSize: 4096, ExtendedRCode: 0, Version: 0, Flags: DO, RDataLength: 0 } }"sv, std::format("{}", *message)));
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
            expect(eq("DNSMessage { DNSHeader { ID: 0xCCE7, DNSHeaderFlags { QR: Response, Flags: Authoritative, OpCode: STANDARD_QUERY, ResponseCode: NO_ERROR }, Questions: 1, Answers: 1, Authorities: 0, Additionals: 1 }, DNSQuestion { Name: o-o.myaddr.l.google.com, Type: TXT, Class: IN }, DNSResourceRecord { Name: o-o.myaddr.l.google.com, Type: TXT, Class: IN, TTL: 60, RDataLength: 21, RData_TXT: 198.51.100.39 }, EDNS_ResourceRecord { Type: OPT, UDP_PayloadSize: 4096, ExtendedRCode: 0, Version: 0, Flags: DO, RDataLength: 0 } }"sv, std::format("{}", *message)));
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
            expect(eq(magic_enum::enum_name(static_cast<DNSError>(message.error().value())), magic_enum::enum_name(DNSError::DeserializePrematureEOF))) << buf;
        }
    } | std::vector<std::string_view> {
        "\314\347\204\0\0\1\0\1\0\0\0\0\3o-o\6myaddr\1l\6google\3com\0\0\20\0\1\300\14\0\20\0\1\0\0\0<\0\16\017198.51.100.39"sv,
        "\314\347\204\0\0\1\0\1\0\0\0\0\3o-o\6myaddr\1l\6google\3com\0\0\20\0\1\300\14\0\20\0\1\0\0\0<\0\16\015198.51.100"sv,
        "\314\347\204\0\0\1\0\1\0\0\0\0\3o-o\6myaddr\1l\6google\3com\0\0\20\0\1\300\14\0\20\0\1\0\0\0<\0\0"sv,
        "\314\347\201\200\0\1\0\1\0\0\0\0\4myip\7opendns\3com\0\0\1\0\1\300\f\0\1\0\1\0\0\0\0\0\5HnPY!"sv,
        "\314\347\201\200\0\1\0\1\0\0\0\0\4myip\7opendns\3com\0\0\1\0\1\300\f\0\34\0\1\0\0\0\0\0\4HnPY"sv,
        "\314\347\201\200\0\1\0\1\0\0\0\0\4myip\7opendns\3com\0\0\1\0\1\300\f\0\34\0\1\0\0\0\0\0\0210123456789abcdefg"sv,
        "\314\347\201\200\0\1\0\1\0\0\0\0\4myip\7opendns\3com\0\0\1\0\1\300\f\0\34\0\1\0\0\0\0\0\20HnPY"sv,
    };
}
