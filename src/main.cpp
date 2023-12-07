#include <iostream>
#include <cstring>
#include <netdb.h>
#include <httplib.h>
#include <array>
#include <random>
#include <optional>
#include <ranges>
#include <algorithm>
#include <expected>
#include <cxxopts.hpp>
#include <systemd/sd-journal.h>
#include <sys/socket.h>

enum class ServiceType {
    HTTP,
    HTTPS,
    DNS,
    // Add more service types if needed
};

struct Service {
    std::string_view address;
    std::optional<std::string_view> path;
    std::optional<std::string_view> resolver;
    ServiceType type;
};

// Initialize the array using std::to_array
constexpr auto services = std::to_array<Service>({
        {"http://ifconfig.me", "/ip", std::nullopt, ServiceType::HTTP},
        {"https://ifconfig.me", "/ip", std::nullopt, ServiceType::HTTPS},
        {"http://icanhazip.com", "/", std::nullopt, ServiceType::HTTP},
        {"https://icanhazip.com", "/", std::nullopt, ServiceType::HTTPS},
        {"myip.opendns.com", std::nullopt, "resolver1.opendns.com", ServiceType::DNS}
        // Add more services if needed
});
static_assert( std::ranges::all_of(services, [](const auto &s) -> bool { if (s.type == ServiceType::HTTP || s.type == ServiceType::HTTPS) return s.path.has_value(); else return true; }) );
static_assert( std::ranges::all_of(services, [](const auto &s) -> bool { if (s.type == ServiceType::DNS) return s.resolver.has_value(); else return true; }) );

ServiceType stringToServiceType(const std::string& str) {
    if (str == "HTTP") {
        return ServiceType::HTTP;
    } else if (str == "DNS") {
        return ServiceType::DNS;
    } else {
        throw std::invalid_argument("Invalid service type. Use 'HTTP' or 'DNS'.");
    }
}

std::string_view serviceTypeToStringView(ServiceType type)
{
    switch (type) {
        case ServiceType::HTTP: return "HTTP";
            break;
        case ServiceType::HTTPS: return "HTTPS";
            break;
        case ServiceType::DNS: return "DNS";
            break;
        default:
            throw std::invalid_argument("Invalid service type to stringify");
    }
}

std::expected<std::string, httplib::Error> queryHttpPublicIp(bool isVerbose, const Service& service) {
    httplib::Client client(std::string(service.address));
    auto res = client.Get(std::string(*service.path));
    if (res && res->status == 200) {
        return res->body;
    } else {
        auto error_str = httplib::to_string(res.error());
        sd_journal_print(LOG_ERR, "service %s (%s) failed (%u): %s",
                         service.address.data(),
                         serviceTypeToStringView(service.type).data(),
                         res->status,
                         error_str.c_str());
        if (isVerbose) {
            std::cerr <<  "Failed to retrieve public IP from " << serviceTypeToStringView(service.type)
                      << " service: "
                      << res->status;
        }
        return std::unexpected(res.error());
    }
}

std::expected<std::string, int> queryDnsPublicIp(const std::string& host, const std::string& resolver) {
    struct addrinfo hints, *result, *p;
    int status;

    // Set up hints structure
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;  // Allow any address family
    hints.ai_socktype = SOCK_STREAM;

    // Perform DNS resolution for resolver
    if ((status = getaddrinfo(resolver.c_str(), nullptr, &hints, &result)) != 0) {
        if (EAI_SYSTEM == status) {
            sd_journal_perror("getaddrinfo");
            return std::unexpected(errno);
        }
        sd_journal_print(LOG_ERR, "getaddrinfo error: %s", gai_strerror(status));
        return std::unexpected(errno);
    }


    std::vector<std::pair<sockaddr_storage, socklen_t>> resolvedAddrs;

    // Iterate through the results and retrieve the address structures
    for (p = result; p != nullptr; p = p->ai_next) {
        // Get a pointer to the inserted element
        resolvedAddrs.push_back({{}, p->ai_addrlen});
        auto addrPtr = reinterpret_cast<sockaddr*>(&resolvedAddrs.back().first);

        // Copy the address structure based on the family
        std::memcpy(addrPtr, p->ai_addr, p->ai_addrlen);
        if (p->ai_family == AF_INET) {
            reinterpret_cast<struct sockaddr_in*>(addrPtr)->sin_port = htons(53);
        } else if (p->ai_family == AF_INET6) {
            reinterpret_cast<struct sockaddr_in6*>(addrPtr)->sin6_port = htons(53);
        }
    }
    freeaddrinfo(result);

    int lastError = 0;

    // Iterate through resolved addresses and attempt DNS query
    for (const auto& [resolvedAddr, resolvedAddrLen] : resolvedAddrs) {
        int sock = socket(resolvedAddr.ss_family, SOCK_DGRAM, 17);
        if (sock < 0) {
            sd_journal_perror("Error creating socket");
            lastError = errno;
            continue;
        }

        if (connect(sock, reinterpret_cast<const sockaddr*>(&resolvedAddr), resolvedAddrLen) < 0) {
            lastError = errno;
            sd_journal_perror("Error connecting socket");
            continue;
        }

        // Prepare the DNS query
        std::vector<uint8_t> query;
        query.push_back(rand() % 256);  // Query ID
        query.push_back(rand() % 256);  // Query ID
        query.push_back(0x01);
        query.push_back(0x00);

        query.push_back(0x01); // 1 question
        query.push_back(0x00);

        query.push_back(0x00);  // number of answers. should be zero.
        query.push_back(0x00);

        query.push_back(0x00);  // number of authority. should be zero.
        query.push_back(0x00);

        query.push_back(0x00);  // number of additional. should be zero.
        query.push_back(0x00);

        // Add the domain name to the query
/*        size_t pos = 0;
        size_t length = host.length();
        while (pos < length) {
            size_t found = host.find('.', pos);
            if (found == std::string::npos) {
                found = length;
            }
            query.push_back(found - pos);
            pos = found + 1;
            }*/
        std::copy(host.begin(), host.end(), std::back_inserter(query));

        query.push_back(0x00);  // Null terminator for domain name

        query.push_back(0x00);  // Query type A (IPv4 address)
        query.push_back(0x01);

        query.push_back(0x00);  // Query class?
        query.push_back(0x01);

        // Send the DNS query to the resolved DNS server
        ssize_t wrote = 0;
        if ((wrote = write(sock, query.data(), query.size())) < 0) {
            sd_journal_perror("Error sending DNS query");
            lastError = errno;
            close(sock);
            continue;
        } else if (std::cmp_less(wrote, query.size())) {
            sd_journal_print(LOG_ERR, "Short write() %ju not %ju", wrote, query.size());
            close(sock);
            continue;
        }

        std::cerr << "wrote " << wrote << " msg!\n";
        // Receive the DNS response
        std::vector<uint8_t> response(512);  // DNS response can be at most 512 bytes
        ssize_t bytesRead = read(sock, response.data(), response.size());
        close(sock);

        if (bytesRead < 0) {
            sd_journal_print(LOG_ERR, "Error receiving DNS response: %s", strerror(errno));
            lastError = errno;
            continue;
        }
        std::string lol(reinterpret_cast<const char *>(response.data()), bytesRead);
        std::cerr << "read " << bytesRead << " bytes: " << lol << "\n";
        // Parse the DNS response to extract the IPv4 address
        size_t answerPos = 12;  // Start of answer section in DNS response
        size_t answerCount = (response[6] << 8) | response[7];  // Number of answers

        for (size_t i = 0; i < answerCount; ++i) {
            if (response[answerPos] & 0xC0) {
                // Compressed name, not handling in this example
                sd_journal_print(LOG_ERR, "Error: Compressed name in DNS response not supported");
                lastError = EINVAL;
                break;
            } else {
                size_t labelLength = response[answerPos++];
                std::string label(response.begin() + answerPos, response.begin() + answerPos + labelLength);
                answerPos += labelLength;

                // Check if this is an IPv4 address record
                if (response[answerPos] == 0x00 && response[answerPos + 1] == 0x01) {
                    answerPos += 8;  // Skip irrelevant bytes
                    uint32_t ipAddress = (response[answerPos] << 24) | (response[answerPos + 1] << 16) |
                                         (response[answerPos + 2] << 8) | response[answerPos + 3];

                    char ipstr[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &ipAddress, ipstr, INET_ADDRSTRLEN);
                    return ipstr;
                } else {
                    // Skip to the next answer
                    answerPos += (response[answerPos] << 8) | response[answerPos + 1];
                }
            }
        }
    }

    // If the loop finishes without success, return the last encountered error
    sd_journal_print(LOG_ERR, "Failed to retrieve public IP from DNS service");
    return std::unexpected(lastError);
}

std::expected<std::string, bool> queryPublicIp(bool isVerbose, const Service& service) {
    if (service.type == ServiceType::HTTP || service.type == ServiceType::HTTPS) {
        auto res = queryHttpPublicIp(isVerbose, service);
        if (!res) return std::unexpected(false);
        else return res.value();
    } else if (service.type == ServiceType::DNS) {
        auto res = queryDnsPublicIp(service.address.data(), service.resolver->data());
        if (!res) return std::unexpected(false);
        else return res.value();
    } else {
        return "Unknown service type.";
    }
}

int main(int argc, char* argv[]) {
    // Command line option parsing with cxxopts
    cxxopts::Options options("fetchip", "Retrieve public IP from random service");
    options.add_options()
        ("h,help", "Show help")
        ("s,service", "Service type (HTTP or DNS)", cxxopts::value<std::string>())
        ("i,insecure", "Use HTTP instead of HTTPS", cxxopts::value<bool>()->default_value("false"))
        ("v,verbose", "Print verbose output to stderr")
        ;

    try {
        auto result = options.parse(argc, argv);

        if (result.count("help")) {
            std::cout << options.help() << std::endl;
            return 0;
        }

        // Transform the service option into a ServiceType enum
        std::optional<ServiceType> selectedType;

        if (result.count("service")) {
            selectedType = stringToServiceType(result["service"].as<std::string>());
        }

        auto use_secure = !result["insecure"].as<bool>();
        auto secureServices = std::views::filter(services, [use_secure](const auto &service) {
            if (use_secure && service.type == ServiceType::HTTP)
                return false;
            if (!use_secure && service.type == ServiceType::HTTPS)
                return false;
            return true;
        });
        // Filter services based on the selected type
        auto filteredServices = std::ranges::views::filter(secureServices, [selectedType](const auto& service) {
            if (selectedType) {
                return service.type == *selectedType;
            } else {
                return true;
            }
        });
        const size_t num_filteredServices = std::ranges::distance(filteredServices);

        std::cerr << "num services = " << num_filteredServices << '\n';
        // Randomly select a service from the filtered range
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<size_t> dist(0, num_filteredServices - 1);
        auto rng = dist(gen);
        std::cerr << "Got random " << rng << '\n';
        const auto selectedService = *std::views::drop(filteredServices, rng).begin();


        // Print verbose output to stderr
        if (result.count("verbose")) {
            std::cerr << "Selected Service: " << selectedService.address << " ("
                      << serviceTypeToStringView(selectedService.type) << ")\n";
        }

        // Query the selected service for public IP
        const auto publicIp = queryPublicIp(result.count("verbose") > 0, selectedService);

        // Print the result
        if (publicIp) {
            std::cout << publicIp.value() << std::endl;
        }

    } catch (const cxxopts::exceptions::exception& e) {
        std::cerr << "Error parsing options: " << e.what() << std::endl;
        return 1;
    } catch (const std::invalid_argument& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }

    return 0;
}
