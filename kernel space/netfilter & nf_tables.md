## 1. Nền Tảng: Network Stack Trong Kernel

### 1.1. Network Stack Là Gì?

**Network stack trong kernel** không phải một khái niệm mới hay phức tạp - đơn giản là **kernel Linux tự implement toàn bộ TCP/IP stack** tương ứng với các tầng trong mô hình OSI.[^1][^2]

Khi application ở userland (như `curl`, `nc`, CTF binary...) gọi syscall `send()`/`recv()`, packet không đi thẳng ra mạng mà phải **đi qua nhiều tầng xử lý trong kernel**:

```
┌─────────────────────────────────────┐
│  USERLAND                           │
│  Application (curl, nc, CTF...)     │
│         │                            │
│         ▼ syscall (send/recv)       │
└─────────────────────────────────────┘
         │
         ▼
┌─────────────────────────────────────┐
│  KERNEL (Network Stack)             │
│                                     │
│  1. Socket Layer                    │
│     - struct socket, struct sock    │
│                                     │
│  2. Transport Layer (TCP/UDP)       │
│     - Port, seq, retransmit...      │
│                                     │
│  3. Network Layer (IP)              │
│     - Routing, IP header, TTL...    │
│                                     │
│  4. Link Layer (Ethernet)           │
│     - MAC, frame                    │
│                                     │
│  5. Driver + NIC                    │
│     - DMA, interrupt, hardware      │
└─────────────────────────────────────┘
```


### 1.2. Kernel Implement Những Tầng Nào?

**Quan trọng**: Kernel **không** implement Application layer - đó là việc của userland program.

Kernel chủ yếu implement:

- **Transport layer**: TCP, UDP, SCTP...
- **Network layer**: IPv4, IPv6, routing, ICMP...
- **Link layer**: Ethernet, VLAN, PPPoE... + NIC driver

Tất cả code xử lý packet sau khi rời app đều nằm trong kernel - parse/đóng gói header, tính checksum, routing, quản lý TCP state machine, v.v.[^2][^3]

***

## 2. Netfilter: Framework Cho Packet Filtering

### 2.1. Netfilter Là Gì?

**Netfilter** là một **framework** trong kernel Linux, cung cấp cơ chế để **chặn và xử lý packet** tại các điểm cố định trên đường đi của packet trong network stack.[^4][^5]

Netfilter **không phải** là firewall - nó chỉ là **hạ tầng** để các firewall (iptables, nftables) hoặc module khác có thể "ngồi" lên đó.

### 2.2. Hook Là Gì?

**Hook** (hay **hook point**) là **các mốc cố định** được cài đặt sẵn trên đường đi của packet trong network stack.[^6][^7]

Khi packet đi đến một hook point:

1. Netfilter gọi lần lượt các **callback** đã đăng ký tại hook đó
2. Mỗi callback nhận packet (`struct sk_buff *skb`) và trả về **verdict**:
    - `NF_ACCEPT` → cho packet đi tiếp
    - `NF_DROP` → bỏ packet
    - `NF_QUEUE`, `NF_STOLEN`, `NF_REPEAT`... (các verdict nâng cao)
3. Dựa trên verdict, netfilter quyết định packet đi tiếp hay dừng

**Analogy**: Hook giống như **các chốt bảo vệ** trên đường, mỗi chốt có nhiều bảo vệ (callback) kiểm tra và quyết định cho qua hay chặn.

### 2.3. Các Hook Points Chính

Netfilter định nghĩa 5 hook points chính cho IPv4/IPv6:[^7][^8][^6]

```
           ┌─────────────────────────────────────┐
  Packet   │                                     │
  vào ──►  │  PREROUTING                         │
           │  (trước routing decision)           │
           └──────────┬──────────────────────────┘
                      │
            ┌─────────▼──────────┐
            │  Routing Decision  │
            └─────────┬──────────┘
                      │
          ┌───────────┼──────────────┐
          │           │              │
          ▼           ▼              ▼
    ┌─────────┐  ┌─────────┐   ┌──────────┐
    │  INPUT  │  │ FORWARD │   │  OUTPUT  │
    │(to local│  │(router) │   │(from app)│
    └────┬────┘  └────┬────┘   └─────┬────┘
         │            │               │
         ▼            │               │
    Local App        │               │
         │            └───────┬───────┘
         │                    │
         └────────────────┬───┘
                          ▼
                   ┌─────────────┐
                   │ POSTROUTING │
                   │(trước ra NIC)│
                   └──────┬──────┘
                          │
                          ▼
                     Ra ngoài
```

**3 đường đi packet chính**:

1. **Local delivery** (đích là máy này):
`PREROUTING → INPUT → Local App`
2. **Forward** (máy đóng vai trò router):
`PREROUTING → FORWARD → POSTROUTING`
3. **Local outbound** (app gửi ra ngoài):
`Local App → OUTPUT → POSTROUTING`

### 2.4. Netfilter Framework Cung Cấp Gì?

Netfilter không chỉ là "có vài hook", mà cung cấp toàn bộ hạ tầng:[^9][^10]

1. **Định nghĩa hook points cố định** (`NF_INET_PRE_ROUTING`, `NF_INET_LOCAL_IN`...)
2. **API để module đăng ký callback** (qua `struct nf_hook_ops`)
3. **Gọi callback và xử lý verdict** khi packet chạm hook
4. **API cho userland** (thông qua iptables/nftables) để config rule

***

## 3. iptables: Kiến Trúc Cũ (2001)

### 3.1. Cách Hoạt Động

**iptables** là bộ tool + kernel module để xử lý packet filtering, sử dụng netfilter framework.[^11]

Mỗi rule bạn viết được **hardcode thành chuỗi match + target**:

```bash
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
         │         │                  │
         chain     match              target
```

- **Match**: điều kiện để khớp packet (`-p tcp`, `--dport 22`, `-s IP`...)
- **Target**: hành động khi khớp (`ACCEPT`, `DROP`, `REJECT`, `LOG`, `DNAT`...)


### 3.2. Kiến Trúc Phân Mảnh

iptables có **nhiều module riêng biệt** cho từng protocol:

- `ip_tables` cho IPv4
- `ip6_tables` cho IPv6
- `arp_tables` cho ARP
- `ebtables` cho bridging

Mỗi module có bộ **x_tables extension** riêng để xử lý match/target.[^12][^11]

### 3.3. Vấn Đề

- **Phân mảnh**: filter IPv4 + IPv6 phải dùng 2 tool khác nhau (`iptables`, `ip6tables`)
- **Hiệu năng kém**: rule được xử lý **tuần tự từ trên xuống** (linear search)
- **Khó mở rộng**: thêm tính năng = phải viết kernel module mới
- **Không atomic**: mỗi lệnh gửi 1 request riêng, có khoảng hở giữa các update[^13][^14]

***

## 4. nftables: Kiến Trúc Mới (2014)

### 4.1. Ý Tưởng Cốt Lõi: Virtual Machine

Thay vì hardcode match/target, nftables implement một **mini VM** (Virtual Machine) trong kernel.[^15][^16]

**VM này không phải** VM như VirtualBox - nó là một **bộ thông dịch bytecode đơn giản** để xử lý packet.

### 4.2. Cách Hoạt Động

```
┌─────────────────────────────────────┐
│  USERLAND                           │
│  ┌───────────────────────────────┐  │
│  │  nft (tool)                   │  │
│  │  1. Parse rule text           │  │
│  │  2. Compile → bytecode        │  │
│  │  3. Send via netlink          │  │
│  └────────────┬──────────────────┘  │
└───────────────│─────────────────────┘
                │ netlink socket
                ▼
┌─────────────────────────────────────┐
│  KERNEL                             │
│  ┌───────────────────────────────┐  │
│  │  nf_tables subsystem          │  │
│  │  - Receive bytecode           │  │
│  │  - Store in table/chain       │  │
│  │  - VM executes when packet    │  │
│  │    hits hook                  │  │
│  └───────────────────────────────┘  │
└─────────────────────────────────────┘
```

Khi packet đến hook:

1. VM đọc bytecode
2. Thực thi từng instruction: load data từ packet, compare, lookup set, jump chain, trả verdict...
3. Trả kết quả: ACCEPT/DROP/...

### 4.3. Bytecode Là Gì?

**Bytecode** = chuỗi instruction được mã hóa thành byte, để VM hiểu và thực thi.

Ví dụ rule: "Nếu port đích = 22, thì ACCEPT"

Bytecode (đơn giản hóa):

```
[load tcp dport]  → đọc 2 byte destination port từ packet
[compare 22]      → so sánh với 22
[verdict accept]  → nếu bằng, trả ACCEPT
```

Trong nftables thực tế, bytecode gồm các **expression** như:

- `nft_payload` – đọc dữ liệu từ packet
- `nft_cmp` – so sánh
- `nft_immediate` – set verdict
- `nft_lookup` – tra cứu trong set[^17][^18]


### 4.4. Ưu Điểm So Với iptables

| Khía cạnh | iptables | nftables |
| :-- | :-- | :-- |
| IPv4 + IPv6 | 2 tool riêng | 1 tool, dùng family `inet` [^19][^20] |
| Thêm tính năng | Cần kernel module mới | Chỉ cần thêm instruction cho VM [^16] |
| Lookup | Linear O(n) | Có set/map với O(1) [^13][^21] |
| Multiple actions | Phải tách rule | 1 rule nhiều action [^14] |
| Atomic update | Không | Có (batch request) [^13] |
| Syntax | Phức tạp | Đơn giản, nhất quán [^19] |

**Ví dụ cụ thể**: Cho phép SSH với cả IPv4 và IPv6

**iptables** - cần 2 lệnh:

```bash
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
ip6tables -A INPUT -p tcp --dport 22 -j ACCEPT
```

**nftables** - chỉ 1 lệnh:

```bash
nft add rule inet filter input tcp dport 22 accept
```


### 4.5. Framework Thống Nhất (Analogy OOP)

**iptables** = nhiều concrete class riêng lẻ, code lặp lại

**nftables** = một abstract framework, nhiều "family" implement:

```
┌──────────────────────────────────────┐
│  nf_tables (abstract framework)      │
│  - Table, chain, rule, expression    │
│  - VM execute bytecode               │
│  - Unified API via netlink           │
└────┬──────────┬──────────┬───────────┘
     │          │          │
     ▼          ▼          ▼
  ┌────┐    ┌─────┐    ┌──────┐
  │ ip │    │ ip6 │    │ inet │ ← families
  │(v4)│    │(v6) │    │(both)│
  └────┘    └─────┘    └──────┘
```

Tất cả family share cùng VM, bytecode format, API.[^16]

***

## 5. Kiến Trúc Chi Tiết nftables

### 5.1. Subsystem Trong Kernel

**Kernel** được chia thành các **subsystem** (phòng ban):

- Memory management
- Scheduler
- VFS
- **Networking** ← netfilter/nf_tables nằm đây
- Device drivers

**Netfilter/nf_tables** là một phần của **networking subsystem**.

### 5.2. Cấu Trúc Phân Cấp

```
TABLE
 │
 ├── CHAIN
 │    │
 │    ├── RULE
 │    │    └── [expression] [expression] ... [statement]
 │    │
 │    └── RULE
 │         └── [expression] [expression] ... [statement]
 │
 ├── SET
 │    └── {element, element, ...}
 │
 └── OBJECT
      └── (counter, quota, limit...)
```


### 5.3. Table (Bảng)

**Table** = container lớn nhất, chứa chains, sets, objects.[^22]

Mỗi table thuộc một **family**:

- `ip` – IPv4 only
- `ip6` – IPv6 only
- `inet` – cả IPv4 và IPv6
- `arp` – ARP
- `bridge` – Ethernet bridging
- `netdev` – ingress/egress (trước network stack)

**Ví dụ**:

```bash
nft add table inet myfilter
#           ^^^^  ^^^^^^^^^
#           family   name
```


### 5.4. Chain (Chuỗi)

**Chain** = container chứa rules, và **gắn vào hook** của netfilter.[^23]

**2 loại chain**:

1. **Base chain**: gắn trực tiếp vào netfilter hook

```bash
nft add chain inet myfilter input { 
    type filter hook input priority 0 ; policy accept ; 
}
```

2. **Regular chain**: không gắn hook, dùng để jump đến (tổ chức code)

### 5.5. Rule (Luật)

**Rule** = một dòng xử lý packet, gồm:[^24]

- **Expressions**: điều kiện kiểm tra packet
- **Statements**: hành động nếu khớp

```bash
nft add rule inet filter input tcp dport 22 accept
#                             ^^^^^^^^^^^^^ ^^^^^^
#                             expressions   statement
```


### 5.6. Expression (Biểu thức)

**Expression** = tạo ra giá trị hoặc điều kiện để so khớp packet.[^25][^17]

Các loại expression:


| Expression | Chức năng | Ví dụ |
| :-- | :-- | :-- |
| `payload` | Đọc từ packet header | `tcp dport`, `ip saddr` |
| `meta` | Metadata (interface, mark) | `meta iifname "eth0"` |
| `cmp` | So sánh | `dport 22` |
| `lookup` | Tìm trong set | `ip saddr @blocked` |
| `ct` | Connection tracking | `ct state established` |

### 5.7. Statement (Câu lệnh)

**Statement** = hành động thực hiện.[^24]


| Statement | Chức năng |
| :-- | :-- |
| `accept` | Cho qua |
| `drop` | Bỏ (im lặng) |
| `reject` | Bỏ + gửi lỗi |
| `jump <chain>` | Nhảy chain khác |
| `counter` | Đếm packet |
| `log` | Ghi log |
| `nat` | NAT (SNAT/DNAT) |

**Ví dụ multiple statements**:

```bash
nft add rule inet filter input tcp dport 22 counter log accept
#                                          ^^^^^^^^^^^^^^^^^^^
#                                          3 statements
```


### 5.8. Set (Tập hợp)

**Set** = danh sách phần tử, dùng để lookup nhanh O(1).[^26][^24]

**Named set**:

```bash
# Tạo set
nft add set inet filter blocked { type ipv4_addr ; }

# Thêm phần tử
nft add element inet filter blocked { 1.2.3.4, 5.6.7.8 }

# Dùng trong rule
nft add rule inet filter input ip saddr @blocked drop
```

**Anonymous set** (inline):

```bash
nft add rule inet filter input tcp dport { 22, 80, 443 } accept
#                                        ^^^^^^^^^^^^^^^^
#                                        anonymous set
```


### 5.9. Anonymous Set vs Named Set

| Thuộc tính | Anonymous set | Named set |
| :-- | :-- | :-- |
| Có tên | Không | Có (@name) |
| Khai báo | Inline trong rule | Tạo trước bằng `add set` |
| Dùng nhiều rule? | Không | Có |
| Cập nhật được? | Không (immutable) | Có (add/del element) |
| Khi nào bị xóa? | Khi rule bị xóa | Khi `delete set` hoặc table bị xóa |

**Anonymous set** bị xóa **implicitly** khi:

- Xóa rule chứa nó
- Xóa chain/table chứa rule đó

**Named set** chỉ bị xóa khi:

- `delete set` (explicit)
- Xóa table chứa nó (implicit)


### 5.10. Map (Bản đồ)

**Map** = set đặc biệt, ánh xạ key → value.[^25][^24]

```bash
# Port → IP đích (DNAT)
nft add map inet filter portmap { type inet_service : ipv4_addr ; }
nft add element inet filter portmap { 80 : 192.168.1.10, 443 : 192.168.1.20 }
nft add rule inet filter prerouting dnat to tcp dport map @portmap
```


### 5.11. Object (Đối tượng)

**Object** = lưu trạng thái, dùng chung giữa nhiều rule.[^27]

Các loại: `counter`, `quota`, `limit`, `ct helper`

```bash
# Tạo counter
nft add counter inet filter http_counter

# Dùng trong rule
nft add rule inet filter input tcp dport 80 counter name http_counter accept
```


### 5.12. Ví Dụ Ruleset Hoàn Chỉnh

```bash
# Tạo table
nft add table inet firewall

# Tạo named set
nft add set inet firewall trusted { type ipv4_addr ; }
nft add element inet firewall trusted { 192.168.1.100, 10.0.0.5 }

# Tạo counter object
nft add counter inet firewall ssh_count

# Tạo base chain
nft add chain inet firewall input { 
    type filter hook input priority 0 ; policy drop ; 
}

# Thêm rules
nft add rule inet firewall input ct state established,related accept
nft add rule inet firewall input ip saddr @trusted tcp dport 22 counter name ssh_count accept
nft add rule inet firewall input tcp dport { 80, 443 } accept
```

Giải thích:

- Default policy: DROP
- Cho phép connection đã thiết lập
- Chỉ IP trong set `trusted` mới SSH được (đếm bằng counter)
- HTTP/HTTPS mở cho mọi IP
- Dùng anonymous set `{80, 443}` vì không cần update

***

## 6. Family và Hook Availability

**Quan trọng**: Không phải mọi family đều dùng được mọi hook.[^23][^24]


| Family | Hooks available |
| :-- | :-- |
| `ip`, `ip6`, `inet` | prerouting, input, forward, output, postrouting, (ingress) |
| `arp`, `bridge` | input, output, (forward cho bridge) |
| `netdev` | ingress, egress (không có input/output/forward) |

**Lý do**: hook nào có ý nghĩa ở "tầng" nào thì family ở tầng đó mới có hook tương ứng:

- `netdev` ở L2 → dùng ingress/egress
- `ip/ip6/inet` ở L3 → có đủ prerouting/input/forward/output/postrouting

Callback trong netfilter được đăng ký ở **kernel**, không phải ở userland.

### Đăng ký callback thế nào?

Kernel module (hoặc code của iptables/nftables) tạo một `struct nf_hook_ops`:

```c
static struct nf_hook_ops ops = {
    .hook     = my_hook_func,        // callback
    .pf       = NFPROTO_INET,        // family (ip/inet/...)
    .hooknum  = NF_INET_PRE_ROUTING, // hook point
    .priority = NF_IP_PRI_FILTER,    // độ ưu tiên
};
```

Sau đó gọi:

```c
nf_register_net_hook(&init_net, &ops);
```

Từ đó, mỗi khi packet tới hook tương ứng, **netfilter sẽ gọi `my_hook_func()`** và đọc verdict nó trả về.

### iptables / nftables có tự đăng ký callback không?

Có, nhưng:

- **Không phải userland tool (`iptables`, `nft`) đăng ký**,  
  mà **các kernel module tương ứng** làm việc đó:

  - iptables: module `ip_tables`, `ip6_tables`, `x_tables`, v.v.  
    → chúng đăng ký hook callback (ví dụ `iptable_filter_hook`) cho các hook như `LOCAL_IN`, `FORWARD`, `LOCAL_OUT`… rồi bên trong gọi hàm xử lý ruleset (`ipt_do_table()`…).

  - nftables: subsystem `nf_tables` trong kernel  
    → khi bạn tạo **base chain** với `type ... hook input ...`, kernel sẽ đăng ký một callback cho hook `INPUT`. Callback này là code VM của nf_tables, nó sẽ chạy bytecode/rule tương ứng với chain đó.

***

## 7. Atomic Update và Batch Request

### 7.1. Vấn Đề Với iptables

Mỗi lệnh iptables gửi **1 request riêng** xuống kernel:

```bash
iptables -A INPUT -p tcp --dport 22 -j ACCEPT   # request 1
iptables -A INPUT -p tcp --dport 80 -j ACCEPT   # request 2
```

**Hậu quả**:

- **Race condition**: giữa 2 rule có khoảng thời gian không nhất quán
- **Security gap**: khi xóa rule cũ và thêm mới, có "lỗ hổng"
- **Performance**: mỗi lần lock/unlock


### 7.2. Giải Pháp: Atomic + Batch

**Atomic** = "tất cả hoặc không gì cả" (all-or-nothing).[^28][^13]

**Batch** = gom nhiều thao tác vào **1 request** gửi qua netlink.[^27]

```
┌─────────────────────────────────────┐
│  BATCH_BEGIN                        │
├─────────────────────────────────────┤
│  NEWTABLE                           │
│  NEWCHAIN                           │
│  NEWRULE                            │
│  NEWRULE                            │
│  DELRULE                            │
├─────────────────────────────────────┤
│  BATCH_END                          │
└─────────────────────────────────────┘
```

Kernel:

1. **Validate tất cả** trước
2. Nếu OK → **commit toàn bộ cùng lúc**
3. Nếu lỗi → **rollback tất cả**

### 7.3. Ví Dụ Thực Tế

File `/etc/nftables.conf`:

```bash
#!/usr/sbin/nft -f

flush ruleset

table inet firewall {
    chain input {
        type filter hook input priority 0; policy drop;
        ct state established,related accept
        tcp dport 22 accept
        tcp dport 80 accept
    }
}
```

Apply:

```bash
nft -f /etc/nftables.conf
```

Tool `nft` biên dịch thành **1 batch duy nhất** gửi xuống kernel. Không có khoảng hở giữa `flush` và rules mới![^20][^13]

### 7.4. Kernel Xử Lý Batch

```
1. CONTROL PLANE
   - Parse từng message
   - Validate: table tồn tại? chain hợp lệ?
   - Tạo object tạm (chưa active)
   - Nếu lỗi → abort

2. COMMIT PHASE (nếu OK)
   - nf_tables_commit() được gọi
   - Tăng "generation number"
   - Activate object mới
   - Unlink object cũ
   - Queue worker để destroy
```

**Generation number**: mỗi lần commit tăng lên. Packet chỉ xử lý rule thuộc generation hiện tại.[^29]

***

## 8. Tại Sao Quan Trọng Cho Security Research?

### 8.1. Attack Surface Của nftables

**VM + bytecode trong kernel** = attack surface mới:

- **Bytecode parsing**: bug trong parse instruction có thể dẫn đến kernel exploit
- **VM execution**: bug trong thực thi (OOB, type confusion)
- **Expression handling**: các expression phức tạp (set, map, payload...) có nhiều edge case
- **Batch processing**: xử lý nhiều thao tác phức tạp trong 1 transaction → race condition, UAF[^30][^29]


### 8.2. Bug Patterns Thường Gặp

1. **Use-After-Free (UAF)** trong batch:

```
Batch:
1. NEWCHAIN "chain1"
2. DELCHAIN "chain1"  ← xóa ngay sau tạo
3. NEWRULE reference "chain1"  ← reference chain đã free?
```

2. **Type confusion** trong expression: VM xử lý sai loại data
3. **OOB access** khi load payload từ packet
4. **Integer overflow** trong set size, element count
5. **Race condition** giữa control plane và data plane

### 8.3. CVE Gần Đây

Nhiều CVE liên quan nf_tables: UAF, OOB, type confusion trong xử lý expression/set, batch processing.[^29]

### 8.4. Điểm Cần Chú Ý

- **Netfilter hooks** chạy trong **softirq context** (không thể sleep)
- **Batch commit** có phase riêng biệt (control plane vs commit)
- **Generation-based lifecycle**: object cũ không bị free ngay
- **Userland có thể gửi bytecode**: ai có `CAP_NET_ADMIN` có thể craft bytecode độc

***

## 9. Tóm Tắt Các Khái Niệm Chính

### 9.1. Thuật Ngữ Cốt Lõi

- **Network stack**: implementation TCP/IP trong kernel (Transport, Network, Link layers)
- **Netfilter**: framework cung cấp hook infrastructure
- **Hook**: mốc trên đường đi packet, nơi callback được gọi
- **Callback**: hàm đăng ký vào hook, trả verdict (ACCEPT/DROP...)
- **iptables**: kiến trúc cũ, hardcode match/target, phân mảnh theo protocol
- **nftables**: kiến trúc mới, dùng VM + bytecode, framework thống nhất
- **VM**: bộ thông dịch bytecode trong kernel
- **Bytecode**: chuỗi instruction để VM thực thi
- **Userland tool (nft)**: parse rule text → compile bytecode → gửi qua netlink


### 9.2. Cấu Trúc nftables

```
TABLE (thuộc family: ip/ip6/inet/arp/bridge/netdev)
 ├── CHAIN (base chain gắn hook, regular chain để jump)
 │    └── RULE (gồm expression + statement)
 ├── SET (named: có tên, cập nhật được | anonymous: inline, immutable)
 ├── MAP (key → value mapping)
 └── OBJECT (counter, quota, limit...)
```


### 9.3. Hook Points

- **PREROUTING**: vừa vào, trước routing
- **INPUT**: packet đến local app
- **FORWARD**: packet đi qua (router mode)
- **OUTPUT**: packet từ local app
- **POSTROUTING**: trước ra khỏi máy


### 9.4. So Sánh Nhanh

|  | iptables | nftables |
| :-- | :-- | :-- |
| Kiến trúc | Module riêng/protocol | VM thống nhất |
| IPv4+IPv6 | 2 tool | 1 tool (family inet) |
| Thêm tính năng | Kernel module mới | Instruction mới |
| Lookup | Linear O(n) | Set/map O(1) |
| Update | Từng request | Atomic batch |
| Syntax | Phức tạp | Đơn giản |

[^1]: https://dev.to/amrelhusseiny/linux-networking-part-1-kernel-net-stack-180l

[^2]: https://www.linkedin.com/pulse/user-space-kernel-build-your-own-linux-network-stack-mohit-mishra-rs5ec

[^3]: https://linux-kernel-labs.github.io/refs/heads/master/labs/networking.html

[^4]: https://blogs.oracle.com/linux/introduction-to-netfilter

[^5]: https://en.wikipedia.org/wiki/Netfilter

[^6]: https://www.digitalocean.com/community/tutorials/a-deep-dive-into-iptables-and-netfilter-architecture

[^7]: https://www.teldat.com/blog/nftables-and-netfilter-hooks-via-linux-kernel/

[^8]: https://thermalcircle.de/doku.php?id=blog%3Alinux%3Anftables_packet_flow_netfilter_hooks_detail

[^9]: https://www.netfilter.org/documentation/HOWTO/netfilter-hacking-HOWTO-3.html

[^10]: https://kernelnewbies.org/Documents/Netfilter

[^11]: https://en.wikipedia.org/wiki/Iptables

[^12]: https://stackoverflow.com/questions/2023578/list-of-loaded-iptables-modules

[^13]: https://dev.to/farshad_nick/iptables-vs-nftables-whats-new-in-linux-firewalling-4a36

[^14]: https://linux-audit.com/networking/nftables/differences-between-iptables-and-nftables-explained/

[^15]: https://en.wikipedia.org/wiki/Nftables

[^16]: https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/configuring_and_managing_networking/getting-started-with-nftables_configuring-and-managing-networking

[^17]: https://zasdfgbnm.github.io/2017/09/07/Extending-nftables/

[^18]: https://github.com/Mic92/nftables/blob/master/src/expression.c

[^19]: https://tuxcare.com/blog/iptables-vs-nftables/

[^20]: https://www.zenarmor.com/docs/linux-tutorials/nftables-vs-iptables-linux-firewall-setup

[^21]: https://www.baeldung.com/linux/ufw-nftables-iptables-comparison

[^22]: https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/7/html/security_guide/sec-creating_and_managing_nftables_tables_chains_and_rules

[^23]: https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains

[^24]: https://www.netfilter.org/projects/nftables/manpage.html

[^25]: https://manpages.debian.org/testing/nftables/nft.8.en.html

[^26]: https://wiki.nftables.org/wiki-nftables/index.php/Sets

[^27]: https://docs.kernel.org/netlink/specs/nftables.html

[^28]: https://notes.suhaib.in/docs/tech/utilities/iptables-nftables-and-you-a-friendly-guide-to-traffic-rules/

[^29]: https://starlabs.sg/blog/2023/09-nftables-adventures-bug-hunting-and-n-day-exploitation/

[^30]: https://kaligulaarmblessed.github.io/post/nftables-adventures-1/

