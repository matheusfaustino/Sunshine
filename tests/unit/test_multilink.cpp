/**
 * @file tests/unit/test_multilink.cpp
 * @brief Test src/multilink.h
 */

// test includes
#include "../tests_common.h"

// local includes
#include <src/multilink.h>

TEST(MultilinkTest, PacksHostOrderAddressWithoutLosingHighBits) {
  EXPECT_EQ(multilink::pack(0xc0a844a8u, 48098), 0xc0a844a8bbe2ull);
  EXPECT_EQ(multilink::pack(0xffffffffu, 65535), 0xffffffffffffull);
  EXPECT_EQ(multilink::pack(0, 0), 0);
}

TEST(MultilinkTest, ParsesOnlyVersionOnePathOneAssociation) {
  std::string d = std::string("MLMP") + '\x01' + "0123456789abcdef" + '\x01';
  ASSERT_EQ(d.size(), multilink::ASSOC_SIZE);
  EXPECT_EQ(multilink::parse_association(d), "0123456789abcdef");

  auto bad = d;
  bad[4] = 2;
  EXPECT_FALSE(multilink::parse_association(bad));
  bad = d;
  bad[21] = 0;
  EXPECT_FALSE(multilink::parse_association(bad));
  bad = d;
  bad[0] = 'X';
  EXPECT_FALSE(multilink::parse_association(bad));
  EXPECT_FALSE(multilink::parse_association(d.substr(0, 21)));
}

TEST(MultilinkTest, TokenBucketLimitsAndRefills) {
  using namespace std::chrono_literals;
  multilink::token_bucket_t bucket {10, 2};
  auto t = std::chrono::steady_clock::now();
  EXPECT_TRUE(bucket.take(1, t));
  EXPECT_TRUE(bucket.take(1, t));
  EXPECT_FALSE(bucket.take(1, t));
  EXPECT_TRUE(bucket.take(1, t + 100ms));

  multilink::token_bucket_t unlimited;
  EXPECT_TRUE(unlimited.take(1e12, t));
}
