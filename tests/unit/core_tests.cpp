#include <string>
#include <vector>

#include "harness.hpp"
#include "icf/core/bytes.hpp"
#include "icf/core/checked.hpp"
#include "icf/core/config.hpp"
#include "icf/core/hash.hpp"
#include "icf/core/ids.hpp"
#include "icf/core/rng.hpp"
#include "icf/core/time.hpp"
#include "icf/core/utf8.hpp"

using namespace icf;

ICF_TEST(hash, crc32c_known_answers) {
  // CRC32C ("iSCSI") check value from RFC 3720 appendix B.
  ICF_EXPECT_EQ(0xE3069283u, crc32c(std::string_view("123456789")));
  ICF_EXPECT_EQ(0u, crc32c(std::string_view("")));
}

ICF_TEST(hash, sha256_known_answers) {
  ICF_EXPECT_EQ(std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
                Sha256::hash(std::string_view("abc")).hex());
  ICF_EXPECT_EQ(std::string("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
                Sha256::hash(std::string_view("")).hex());
  ICF_EXPECT_EQ(std::string("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
                Sha256::hash(std::string_view(
                                 "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))
                    .hex());
  // A message that spans several blocks exercises the streaming path.
  std::string long_message(1000, 'a');
  ICF_EXPECT_EQ(std::string("41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3"),
                Sha256::hash(std::string_view(long_message)).hex());
}

ICF_TEST(hash, hmac_rfc4231_case_one) {
  std::vector<std::byte> key(20, std::byte{0x0b});
  const std::string message = "Hi There";
  const Digest mac = hmac_sha256(key, std::span<const std::byte>(reinterpret_cast<const std::byte*>(message.data()),
                                                                 message.size()));
  ICF_EXPECT_EQ(std::string("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"), mac.hex());
}

ICF_TEST(hash, digest_parse_and_compare) {
  const Digest digest = Sha256::hash(std::string_view("abc"));
  Result<Digest> parsed = Digest::parse_hex(digest.hex());
  ICF_ASSERT_TRUE(parsed.has_value());
  ICF_EXPECT_TRUE(parsed.value() == digest);
  ICF_EXPECT_FALSE(parsed.value() < digest);
  ICF_EXPECT_OUTCOME(Outcome::Invalid, Digest::parse_hex("zz"));
  ICF_EXPECT_OUTCOME(Outcome::Invalid, Digest::parse_hex(std::string(63, 'a')));
}

ICF_TEST(utf8, accepts_valid_and_rejects_malformed) {
  ICF_EXPECT_TRUE(is_valid_utf8("plain ascii"));
  ICF_EXPECT_TRUE(is_valid_utf8("caf\xc3\xa9"));
  ICF_EXPECT_TRUE(is_valid_utf8("\xf0\x9f\x9a\x80"));
  ICF_EXPECT_FALSE(is_valid_utf8("\xc0\x80"));            // overlong
  ICF_EXPECT_FALSE(is_valid_utf8("\xed\xa0\x80"));        // surrogate half
  ICF_EXPECT_FALSE(is_valid_utf8("\xf4\x90\x80\x80"));   // above U+10FFFF
  ICF_EXPECT_FALSE(is_valid_utf8("\xe2\x82"));             // truncated
  ICF_EXPECT_FALSE(is_valid_utf8("\x80"));                  // stray continuation
}

ICF_TEST(checked, arithmetic_bounds) {
  std::uint64_t out = 0;
  ICF_EXPECT_TRUE(checked::add_u64(1, 2, out));
  ICF_EXPECT_EQ(3ull, out);
  ICF_EXPECT_FALSE(checked::add_u64(UINT64_MAX, 1, out));
  ICF_EXPECT_FALSE(checked::mul_u64(UINT64_MAX, 2, out));
  ICF_EXPECT_TRUE(checked::sub_u64(5, 5, out));
  ICF_EXPECT_EQ(0ull, out);
  ICF_EXPECT_FALSE(checked::sub_u64(0, 1, out));
  std::uint32_t narrowed = 0;
  ICF_EXPECT_FALSE(checked::to_u32(1ull << 32, narrowed));
  ICF_EXPECT_TRUE(checked::to_u32(7, narrowed));
  ICF_EXPECT_EQ(7u, narrowed);
}

ICF_TEST(bytes, round_trip_and_bounds) {
  ByteWriter writer;
  writer.u8(0xAB);
  writer.u16(0x1234);
  writer.u32(0xDEADBEEF);
  writer.u64(0x0123456789ABCDEFull);
  writer.i64(-42);
  writer.boolean(true);
  writer.blob("hello");
  writer.digest(Sha256::hash(std::string_view("x")));
  const std::vector<std::byte> bytes = writer.data();

  ByteReader reader(bytes);
  ICF_EXPECT_EQ(0xABu, reader.u8().value());
  ICF_EXPECT_EQ(0x1234u, reader.u16().value());
  ICF_EXPECT_EQ(0xDEADBEEFu, reader.u32().value());
  ICF_EXPECT_EQ(0x0123456789ABCDEFull, reader.u64().value());
  ICF_EXPECT_EQ(-42, reader.i64().value());
  ICF_EXPECT_EQ(true, reader.boolean().value());
  ICF_EXPECT_EQ(std::string("hello"), reader.blob(64).value());
  ICF_EXPECT_OK(reader.digest());
  ICF_EXPECT_OK(reader.expect_end());

  ByteReader truncated(std::span<const std::byte>(bytes.data(), 3));
  ICF_EXPECT_OUTCOME(Outcome::Incomplete, truncated.u32());

  ByteReader hostile(bytes);
  ICF_EXPECT_OUTCOME(Outcome::Invalid, hostile.blob(2));  // declared length above the caller's maximum
}

ICF_TEST(bytes, rejects_invalid_utf8_and_trailing_bytes) {
  ByteWriter writer;
  writer.u32(2);
  writer.raw(std::span<const std::byte>(reinterpret_cast<const std::byte*>("\xff\xfe"), 2));
  ByteReader reader(writer.data());
  ICF_EXPECT_OUTCOME(Outcome::Invalid, reader.blob(64));

  ByteWriter trailing;
  trailing.u8(1);
  trailing.u8(2);
  ByteReader reader2(trailing.data());
  ICF_EXPECT_EQ(1u, reader2.u8().value());
  ICF_EXPECT_OUTCOME(Outcome::Invalid, reader2.expect_end());
}

ICF_TEST(ids, name_validation) {
  ICF_ASSERT_TRUE(ClusterId::parse("cluster-a.1").has_value());
  ICF_EXPECT_OUTCOME(Outcome::Invalid, ClusterId::parse(""));
  ICF_EXPECT_OUTCOME(Outcome::Invalid, ClusterId::parse("-leading"));
  ICF_EXPECT_OUTCOME(Outcome::Invalid, ClusterId::parse("has space"));
  ICF_EXPECT_OUTCOME(Outcome::Invalid, ClusterId::parse("caf\xc3\xa9"));  // not in the permitted ASCII set
  ICF_EXPECT_OUTCOME(Outcome::Invalid, ClusterId::parse(std::string(200, 'a')));
  ICF_ASSERT_TRUE(ScopeName::parse("/tenant/a:b").has_value());
}

ICF_TEST(ids, uuid_and_counters) {
  Rng rng(1);
  const Uuid id = Uuid::random(rng);
  Result<Uuid> parsed = Uuid::parse(id.to_string());
  ICF_ASSERT_TRUE(parsed.has_value());
  ICF_EXPECT_EQ(id, parsed.value());
  ICF_EXPECT_EQ(static_cast<std::size_t>(36), id.to_string().size());
  ICF_EXPECT_FALSE(id.is_nil());
  ICF_EXPECT_TRUE(Uuid{}.is_nil());
  ICF_EXPECT_OUTCOME(Outcome::Invalid, Uuid::parse("not-a-uuid"));

  Generation generation(4);
  ICF_EXPECT_TRUE(generation.increment());
  ICF_EXPECT_EQ(5ull, generation.value());
  Generation maximum(UINT64_MAX);
  ICF_EXPECT_FALSE(maximum.increment());
  ICF_EXPECT_OUTCOME(Outcome::Overflow, maximum.next());

  ICF_ASSERT_TRUE(Generation::parse("18446744073709551615").has_value());
  ICF_EXPECT_OUTCOME(Outcome::Overflow, Generation::parse("18446744073709551616"));
  ICF_EXPECT_OUTCOME(Outcome::Invalid, Generation::parse("-1"));

  ICF_EXPECT_OUTCOME(Outcome::Overflow, add(CapacityUnits(UINT64_MAX), CapacityUnits(1)));
  ICF_EXPECT_OUTCOME(Outcome::Overflow, subtract(CapacityUnits(0), CapacityUnits(1)));
}

ICF_TEST(time, duration_and_timestamp) {
  ICF_ASSERT_TRUE(Duration::parse("250ms").has_value());
  ICF_EXPECT_EQ(250000000, Duration::parse("250ms").value().nanos());
  ICF_EXPECT_EQ(2000000000, Duration::parse("2s").value().nanos());
  ICF_EXPECT_OUTCOME(Outcome::Invalid, Duration::parse("2s "));
  ICF_EXPECT_OUTCOME(Outcome::Invalid, Duration::parse("s"));
  ICF_EXPECT_OUTCOME(Outcome::Invalid, Duration::parse("2weeks"));
  ICF_EXPECT_OUTCOME(Outcome::Overflow, Duration::parse("999999999999999999h"));

  const Timestamp epoch = Timestamp::from_unix_nanos(0);
  ICF_EXPECT_EQ(std::string("1970-01-01T00:00:00.000000000Z"), epoch.to_iso8601());
  const Timestamp known = Timestamp::from_unix_nanos(1700000000123456789);
  ICF_EXPECT_EQ(std::string("2023-11-14T22:13:20.123456789Z"), known.to_iso8601());
  ICF_ASSERT_TRUE(Timestamp::parse_iso8601(known.to_iso8601()).has_value());
  ICF_EXPECT_EQ(known.unix_nanos(), Timestamp::parse_iso8601(known.to_iso8601()).value().unix_nanos());
  ICF_EXPECT_OUTCOME(Outcome::Invalid, Timestamp::parse_iso8601("2023-11-14T22:13:20"));
  ICF_EXPECT_OUTCOME(Outcome::Invalid, Timestamp::parse_iso8601("2023-13-14T22:13:20Z"));

  ManualClock clock(Timestamp::from_unix_nanos(1000));
  ICF_EXPECT_EQ(1000, clock.now().unix_nanos());
  clock.advance(Duration::from_millis(1));
  ICF_EXPECT_EQ(1001000, clock.now().unix_nanos());
  ICF_EXPECT_EQ(1000000, clock.monotonic_nanos());
}

ICF_TEST(rng, deterministic_streams) {
  Rng first(1234);
  Rng second(1234);
  for (int index = 0; index < 32; ++index) {
    ICF_EXPECT_EQ(first.next_u64(), second.next_u64());
  }
  Rng other(1235);
  ICF_EXPECT_NE(first.next_u64(), other.next_u64());
  Rng bounded(99);
  for (int index = 0; index < 1000; ++index) {
    ICF_EXPECT_TRUE(bounded.below(7) < 7);
  }
  ICF_EXPECT_EQ(0ull, bounded.below(1));
  ICF_EXPECT_EQ(5ull, bounded.range(5, 5));
}

ICF_TEST(config, strict_parsing) {
  const std::string text =
      "# comment\n"
      "state_dir = /tmp/icf\n"
      "listen_port = 8080\n"
      "durable = true\n"
      "lease = 30s\n";
  Result<Config> config = Config::parse(text, "test");
  ICF_ASSERT_TRUE(config.has_value());
  ICF_EXPECT_EQ(std::string("/tmp/icf"), config.value().get_string("state_dir").value());
  ICF_EXPECT_EQ(8080ull, config.value().get_u64("listen_port").value());
  ICF_EXPECT_EQ(true, config.value().get_bool("durable").value());
  ICF_EXPECT_EQ(30000000000, config.value().get_duration("lease").value().nanos());
  ICF_EXPECT_OK(config.value().reject_unknown({"state_dir", "listen_port", "durable", "lease"}));
  ICF_EXPECT_OUTCOME(Outcome::Invalid,
                     config.value().reject_unknown({"state_dir", "listen_port", "durable"}));
  ICF_EXPECT_OUTCOME(Outcome::NotFound, config.value().get_string("missing"));
  ICF_EXPECT_OUTCOME(Outcome::Invalid, Config::parse("novalue\n", "test"));
  ICF_EXPECT_OUTCOME(Outcome::Invalid, Config::parse("state_dir = a\nstate_dir = b\n", "test"));
  ICF_EXPECT_OUTCOME(Outcome::Invalid, Config::parse("bad key = 1\n", "test"));
  ICF_EXPECT_OUTCOME(Outcome::Invalid, Config::parse(std::string("key = ") + std::string(600, 'x') + "\n", "test"));
  icf::Result<Config> huge = Config::parse("n = 99999999999999999999999\n", "test");
  ICF_ASSERT_TRUE(huge.has_value());
  ICF_EXPECT_OUTCOME(Outcome::Overflow, huge.value().get_u64("n"));
  std::string many_lines;
  for (int index = 0; index < 600; ++index) {
    many_lines += "k" + std::to_string(index) + " = 1\n";
  }
  ICF_EXPECT_OUTCOME(Outcome::Invalid, Config::parse(many_lines, "test"));
}

ICF_TEST(status, outcome_names_are_distinct) {
  const Outcome outcomes[] = {
      Outcome::Unknown,      Outcome::Unsupported,    Outcome::Stale,        Outcome::Conflicting,
      Outcome::Incomplete,   Outcome::Indeterminate,  Outcome::Refused,      Outcome::Cancelled,
      Outcome::Invalid,      Outcome::Unreachable,    Outcome::Partitioned,  Outcome::DegradedAuthorized,
      Outcome::Fenced,       Outcome::Expired,        Outcome::Unauthorized, Outcome::NotFound,
      Outcome::CapacityExceeded, Outcome::Replayed,   Outcome::Reincarnated, Outcome::Corrupt,
      Outcome::Incompatible, Outcome::Overflow,       Outcome::Busy,         Outcome::AlreadyExists,
      Outcome::Internal,     Outcome::Ok};
  for (const Outcome outcome : outcomes) {
    Outcome parsed = Outcome::Internal;
    ICF_EXPECT_TRUE(outcome_from_string(to_string(outcome), parsed));
    ICF_EXPECT_EQ(outcome, parsed);
  }
  ICF_EXPECT_TRUE(is_authorized(Outcome::Ok));
  ICF_EXPECT_TRUE(is_authorized(Outcome::DegradedAuthorized));
  ICF_EXPECT_FALSE(is_authorized(Outcome::Unknown));
  ICF_EXPECT_FALSE(is_ok(Outcome::DegradedAuthorized));
  ICF_EXPECT_TRUE(is_indeterminate_family(Outcome::Indeterminate));
  ICF_EXPECT_TRUE(is_indeterminate_family(Outcome::Unreachable));
  ICF_EXPECT_FALSE(is_indeterminate_family(Outcome::Refused));
  ICF_EXPECT_FALSE(is_indeterminate_family(Outcome::Ok));
}
