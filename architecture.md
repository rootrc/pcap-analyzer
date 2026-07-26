┌──────────────────────────────────────────┐
│             packet_reader.h              │
│  Reader — mmap pcap file, reads packets  │
└────────────────────┬─────────────────────┘
                     | per packet
                     ▼
            ┌────────────────┐
            │  decoder.cpp   │
            │  decodePacket  │
            │  L2 → L3 → L4  │
            │  fills Packet  │
            │  sets payload  │
            └────────┬───────┘
                     │
                     ▼
        ┌────────────────────────┐
        │    flow_tracker.cpp    │
        │  FlowTable::addPacket  │
        │  flow expiry/timeout   │
        └────────────┬───────────┘
                     │
         ┌───────────┴───────────┐
         │ TCP                   │ UDP
         ▼                       ▼
┌──────────────────┐   ┌─────────────────────┐
│  tcp_stream.h    │   │  payload (Buffer)   │
│  TcpReassembler  │   │  raw datagram, no   │
│  ├ next_seq      │   │  reassembly needed  │
│  ├ out_of_order  │   └─────────┬───────────┘
│  └ assembled     │             │
└────────┬─────────┘             │
         └──────────┬────────────┘
                    ▼
        (application decoder, TODO)