┌──────────────────────────────────────────┐
│              pcap_reader.h               │
│  Reader — mmap pcap file, reads packets  │
└────────────────────┬─────────────────────┘
                     | per packet
                     ▼
              ┌─────────────┐
              │  decoder.h  │
              │   decode    │
              └──────┬──────┘
                     │
                     ▼
          ┌────────────────────┐
          │ packet_decoder.cpp │
          │    decodePacket    │
          │    L2 → L3 → L4    │
          │    fills Packet    │
          │    sets payload    │
          └──────────┬─────────┘
                     │
                     ▼
        ┌────────────────────────┐
        │     flow_table.cpp     │
        │  FlowTable::addPacket  │
        │  flow expiry/timeout   │
        └────────────┬───────────┘
                     │
         ┌───────────┴───────────┐
         │ TCP                   │ UDP
         ▼                       ▼
┌──────────────────┐   ┌─────────────────────┐
│ tcp_reassembler.h│   │  payload (Buffer)   │
│  TcpReassembler  │   │  raw datagram, no   │
│  ├ next_seq      │   │  reassembly needed  │
│  ├ out_of_order  │   └─────────┬───────────┘
│  └ assembled     │             │
└────────┬─────────┘             │
         │                       │
         ▼                       ▼
┌──────────────────┐   ┌─────────────────────┐
│  app_decoder.cpp │   │   app_decoder.cpp   │
│     pollFlow     │   │     pollDatagram    │
└──────────────────┘   └─────────────────────┘