#include <spanstream>
#include "context.hpp"
#include "dns.hpp"
#include "pcg_random.hpp"

#ifndef __AFL_FUZZ_TESTCASE_LEN
  unsigned char fuzz_buf[512];
  #define NOT_AFL
  const auto seed = pcg32{pcg_extras::seed_seq_from<std::random_device>()};
  auto loop_condition = [i = 0,
                         span = std::span<unsigned char, sizeof(fuzz_buf)> {fuzz_buf},
                         gen = [dist = std::uniform_int_distribution<unsigned char> {},
                                rng = seed] mutable { return dist(rng); }
                        ] (int x) mutable {
                               std::ranges::generate(span, gen);
                               return i++ < x;
                        };
  #define __AFL_FUZZ_TESTCASE_LEN (sizeof(fuzz_buf))
  #define __AFL_FUZZ_TESTCASE_BUF fuzz_buf
  #define __AFL_FUZZ_INIT() void sync(void);
  #define __AFL_LOOP(x) (loop_condition(x))
  #define __AFL_INIT() sync()
#endif

__AFL_FUZZ_INIT();

int main() {
#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
#endif

  unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;  // must be after __AFL_INIT
                                                 // and before __AFL_LOOP!
  fip::context ctx(true);

#ifdef NOT_AFL
  std::cerr << "Seed is: " << seed << "\n";
#endif

  while (__AFL_LOOP(10000)) {

    const std::size_t len = __AFL_FUZZ_TESTCASE_LEN;  // don't use the macro directly in a
                                                      // call!

    auto s = std::span<char>(reinterpret_cast<char*>(buf), len);
    std::ispanstream ss(s);

    jump_table_t jump_table;
    auto res = DNSQuestion::deserialize(ctx, ss, jump_table);
    if (res) {
        auto question = res.value();
        [[maybe_unused]] auto header = question.qname;
    } else {
        auto error = res.error();
        auto msg = error.message();
        [[maybe_unused]] auto msg_size = msg.size();
    }
  }

  return 0;

}
