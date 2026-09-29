#include <gtest/gtest.h>
#include <net/flow/tcp_reassembler.h>
#include "common/header_tester.h"
#include "common/random_gen.h"
#include "testgen/protocol_generator.h"

#include <algorithm>
#include <cstring>
#include <vector>

namespace {
    struct Segment {
        uint32_t seq = 0;
        size_t offset = 0;
        size_t len = 0;
    };

    void prime(net::TcpReassembler& stream, uint32_t isn) {
        stream.onSent(testgen::makeTcpSegmentHeader(isn), std::span<const uint8_t>{});
    }

    void send(net::TcpReassembler& stream, const std::vector<uint8_t>& data, const Segment& segment) {
        stream.onSent(testgen::makeTcpSegmentHeader(segment.seq), std::span<const uint8_t>{data.data() + segment.offset, segment.len});
    }

    std::vector<Segment> cutStream(size_t total, uint32_t isn, bool overlap) {
        std::vector<Segment> segments;
        for (size_t pos = 0; pos < total;) {
            size_t len = randomgen::randRange32(1, static_cast<uint32_t>(std::min<size_t>(512, total - pos)));
            segments.push_back({static_cast<uint32_t>(isn + pos), pos, len});
            pos += len;
        }
        if (overlap) {
            for (Segment& segment : segments) {
                size_t back = randomgen::randRange32(0, 64);
                size_t begin = back > segment.offset ? 0 : segment.offset - back;
                size_t end = std::min(total, segment.offset + segment.len + randomgen::randRange32(0, 64));
                segment = {static_cast<uint32_t>(isn + begin), begin, end - begin};
            }
            const size_t original = segments.size();
            for (size_t i = 0; i <= original / 4; ++i) {
                segments.push_back(segments[randomgen::randRange32(0, static_cast<uint32_t>(original - 1))]);
            }
        }
        randomgen::shuffle(segments);
        return segments;
    }

    void expectReassembles(size_t iterations, bool overlap, bool wraparound) {
        for (size_t i = 0; i < iterations; ++i) {
            const size_t total = randomgen::randRange32(1, 8192);
            const std::vector<uint8_t> data = randomgen::randomBytes(total);
            const uint32_t isn = wraparound ? static_cast<uint32_t>(0u - randomgen::randRange32(1, static_cast<uint32_t>(total)))
                                            : randomgen::rand32();

            net::TcpReassembler stream;
            prime(stream, isn);
            for (const Segment& segment : cutStream(total, isn, overlap)) {
                send(stream, data, segment);
            }

            ASSERT_EQ(stream.available(), total)
                << "iteration " << i << ", stream of " << total << " bytes from isn " << isn
                << " (rerun with --seed from this run's output)";
            EXPECT_EQ(std::memcmp(stream.peek().data(), data.data(), total), 0)
                << "iteration " << i << ": reassembled bytes differ from the source stream";
            EXPECT_EQ(stream.next_seq, static_cast<uint32_t>(isn + total));
            EXPECT_TRUE(stream.out_of_order.empty());
            EXPECT_EQ(stream.ooo_bytes, 0u);
        }
    }
}

TEST(TCP_REASSEMBLER, ReassemblesShuffledSegments) {
    expectReassembles(g_randomizedIterations / 2, false, false);
}

TEST(TCP_REASSEMBLER, ReassemblesShuffledOverlappingSegments) {
    expectReassembles(g_randomizedIterations / 2, true, false);
}

TEST(TCP_REASSEMBLER, ReassemblesAcrossSequenceWraparound) {
    expectReassembles(g_randomizedIterations / 2, true, true);
}

TEST(TCP_REASSEMBLER, DropsOutOfOrderBytesPastCap) {
    constexpr uint32_t ISN = 1000;
    constexpr size_t GAP = 4096;
    constexpr size_t CHUNK = 1024;
    constexpr size_t CHUNKS = (net::TcpReassembler::MAX_OOO_BYTES / CHUNK) + 256;

    const std::vector<uint8_t> chunk(CHUNK, 0xAB);
    net::TcpReassembler stream;
    prime(stream, ISN);

    for (size_t i = 0; i < CHUNKS; ++i) {
        stream.onSent(testgen::makeTcpSegmentHeader(static_cast<uint32_t>(ISN + GAP + i * CHUNK)), std::span<const uint8_t>{chunk});
    }

    EXPECT_LE(stream.ooo_bytes, net::TcpReassembler::MAX_OOO_BYTES);
    EXPECT_LT(stream.ooo_bytes, CHUNKS * CHUNK) << "nothing was dropped, so the cap never engaged";
    EXPECT_EQ(stream.available(), 0u);

    const size_t retained = stream.ooo_bytes;
    const std::vector<uint8_t> gap(GAP, 0xCD);
    stream.onSent(testgen::makeTcpSegmentHeader(ISN), std::span<const uint8_t>{gap});

    EXPECT_EQ(stream.available(), GAP + retained);
    EXPECT_EQ(stream.ooo_bytes, 0u);
}

TEST(TCP_REASSEMBLER, ConsumeAdvancesPastCompaction) {
    constexpr uint32_t ISN = 7;
    constexpr size_t TOTAL = 16384;

    const std::vector<uint8_t> data = randomgen::randomBytes(TOTAL);
    net::TcpReassembler stream;
    prime(stream, ISN);
    stream.onSent(testgen::makeTcpSegmentHeader(ISN), std::span<const uint8_t>{data});

    size_t consumed = 0;
    while (consumed < TOTAL) {
        ASSERT_EQ(stream.available(), TOTAL - consumed);
        ASSERT_EQ(std::memcmp(stream.peek().data(), data.data() + consumed, TOTAL - consumed), 0)
            << "peek() diverged from the source stream after consuming " << consumed << " bytes";
        const size_t step = std::min<size_t>(1500, TOTAL - consumed);
        stream.consume(step);
        consumed += step;
    }

    EXPECT_EQ(stream.available(), 0u);
    stream.consume(64);
    EXPECT_EQ(stream.available(), 0u);
}
