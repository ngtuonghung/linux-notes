## Phần 1: Background - Memory Management Cơ Bản

### 1.1 Page - Đơn vị quản lý bộ nhớ

RAM không được quản lý theo từng byte, mà được chia thành các **khối cố định** gọi là **page**:[^4][^5]

- **Kích thước**: thường **4KB** (4096 bytes) trên hầu hết các hệ thống
- **Lý do**: dễ quản lý, căn chỉnh, bảo vệ, giảm phân mảnh[^5][^4]
- Mỗi page có:
    - **Physical address (PA)**: vị trí thật trong RAM
    - **Virtual address (VA)**: địa chỉ mà code nhìn thấy


### 1.2 Virtual Address trên x86-64

Trên kiến trúc x86-64:[^6][^7][^8][^9]

- **Virtual address**: 48-bit được sử dụng thực tế (không phải đủ 64-bit)
- **Physical address**: 36-52 bit tùy CPU (thường 36-48 bit)
- Cấu trúc VA: `VA = page_number + offset_trong_page`
    - Với page 4KB: 12 bit cuối là offset (0-4095)
    - Các bit còn lại: page number để tra page table


### 1.3 Page Table và Address Translation

**Page table** không phải hash map đơn giản, mà là cấu trúc **multi-level** (4-5 level trên x86-64):[^10][^4][^5]

- VA được chia thành: `[Level0 idx][Level1 idx][Level2 idx][Level3 idx][Offset]`
- Mỗi level là array 512 entries (8 bytes/entry)
- MMU duyệt từng level để map VA → PA
- Entry cuối (PTE) chứa **physical page frame number + flags**
- Offset 12 bit cuối giữ nguyên → địa chỉ vật lý cuối cùng


### 1.4 Kernel vs Userland Memory

- **Userland**: dùng **ptmalloc** trên user VA space
- **Kernel**: dùng **buddy allocator + SLUB** trên kernel VA space (privileged, user không truy cập được)[^4][^5]
- Tất cả kernel memory (code, stack, heap, slab, page cache) đều nằm trên các page 4KB này


## Phần 2: Kernel Heap - SLUB Allocator

### 2.1 kmalloc() - Kernel malloc

- Userland: `malloc(size)` → ptmalloc
- Kernel: `kmalloc(size, flags)` → SLUB allocator
- `kmalloc` trả về **kernel virtual address**


### 2.2 SLUB là gì?

**SLUB** = "Unqueued SL**a**b **B**uddy Allocator" - default kernel heap allocator từ Linux 2.6.22.[^11][^12][^13]

Thay vì cấp phát size bất kỳ, kernel dùng **slab cache system**:

### 2.3 Slab Cache (kmalloc-*)

Kernel chuẩn bị sẵn nhiều "bể" cho size cố định:[^12][^11]

```
kmalloc-32   → object 32 bytes
kmalloc-64   → object 64 bytes
kmalloc-128  → object 128 bytes
kmalloc-256  → object 256 bytes
...
```

**Khi gọi `kmalloc(40, GFP_KERNEL)`**:

- Kernel chọn cache phù hợp: `kmalloc-64` (vì 40 ≤ 64)
- Trả về 1 object 64B từ cache đó
- Lý do: quản lý đơn giản, ít phân mảnh, tối ưu per-CPU

**Tương tự tcache**: đều là pool các block cùng size, nhưng khác metadata.

### 2.4 Ba khái niệm quan trọng

#### 2.4.1 Slab Cache

- **Cache toàn cục** cho một size (vd: `kmalloc-64`)
- Quản lý tất cả slab pages thuộc size đó


#### 2.4.2 Slab (Slab Page)

- **1 hoặc vài page 4KB** thuộc một cache
- Mỗi page chia thành nhiều **object** cùng kích thước
- Ví dụ: page 4KB cho `kmalloc-64` → `4096 / 64 ≈ 64 objects`


#### 2.4.3 Object

- **Block cố định** (32B, 64B, ...) mà `kmalloc` trả về
- Layout quan trọng nhất cho exploitation


## Phần 3: Object Layout và Freelist

### 3.1 Object Layout - Điểm khác biệt lớn với ptmalloc

**ptmalloc (userland)**:

```
[size|flags|prev_size] [payload] [next chunk]
      ↑ metadata ngoài chunk
```

**SLUB (kernel)**:

```
Object (64B):
[8B freelist_ptr] [56B user data]
     ↑ metadata TRONG object
```

**Khác biệt cốt lõi**:[^14][^11]


| ptmalloc | SLUB |
| :-- | :-- |
| Metadata **ngoài** chunk | Metadata **TRONG** object |
| Overflow khó chạm metadata | **Overflow → ghi đè freelist ptr** |
| Fake chunk cần size hợp lệ | **Fake object dễ hơn** |

### 3.2 Freelist - Cơ chế quản lý free objects

**Cấu trúc**: singly-linked list, **LIFO** (không phải FIFO):[^11][^12][^14]

```c
Object A (free):  [ptr → Object C] [data 56B]
Object B (alloc): [struct fields...] [data...]
Object C (free):  [ptr → Object F] [data 56B]
Object F (free):  [ptr → NULL] [data 56B]

freelist_head → Object A
```

**Alloc (fastpath)**:

```c
obj = freelist_head;
freelist_head = obj->next;
obj->next = 0;  // clear
return obj;
```

**Free (fastpath)**:

```c
obj->next = freelist_head;
freelist_head = obj;
```

**Không phải liền kề**: các object trong freelist **không cần liên tiếp** trong page, thứ tự phụ thuộc lịch sử alloc/free (LIFO).

## Phần 4: Per-CPU Architecture

### 4.1 Per-CPU State

Mỗi **CPU core** có state riêng để tránh lock:[^13][^12][^11]

```
kmalloc-64 cache:
  CPU 0:
    freelist → Obj5 → Obj12 → NULL
    page → Slab_A (active)
  CPU 1:
    freelist → Obj3 → Obj9 → NULL
    page → Slab_B (active)
  CPU 2:
    freelist → NULL (empty)
  ...
```


### 4.2 Freelist Head cho mỗi CPU

**Câu hỏi quan trọng**: có bao nhiêu freelist head?

**Trả lời**: Mỗi cache (vd `kmalloc-64`) có:

- **Per-CPU freelist head**: mỗi CPU core có 1 head riêng[^14][^11]
- Ban đầu chưa dùng: `freelist = NULL` cho tất cả CPU
- Khi CPU 0 gọi `kmalloc` lần đầu:

1. Buddy allocator cấp page 4KB mới
2. Chia page thành 64 object × 64B
3. Xây freelist: Obj0→Obj1→...→Obj63→NULL
4. `cpu_slab[^0].freelist = &Obj0`


### 4.3 Slab "thuộc về" CPU?

**Không hẳn**, nhưng:

- Mỗi CPU có **1 active slab** (slab đang xài)
- Slab khác nằm trong **partial list chung** (per-node)
- **kmalloc trên CPU X** thường **không ảnh hưởng CPU Y** (fastpath)
- Chỉ khi slowpath (cần refill) mới có tương tác với partial list chung

**Cho exploit**: overflow trên active slab của CPU 0 → trigger kmalloc tiếp trên **CPU 0** → dễ pop fake object.

## Phần 5: SLUB Internal Structures

### 5.1 struct kmem_cache - Slab Cache

```c
struct kmem_cache {
    unsigned int size;          // kích thước 1 object (32, 64,...)
    unsigned int objsize;       // phần usable
    unsigned int offset;        // offset freelist ptr (thường = 0)
    struct kmem_cache_cpu __percpu *cpu_slab; // per-CPU data
    struct kmem_cache_node *node[MAX_NUMNODES]; // per-node data
    ...
};
```

- `offset = 0` → freelist ptr ở 8B đầu object
- `cpu_slab` → mỗi CPU có 1 struct `kmem_cache_cpu`


### 5.2 struct kmem_cache_cpu - Per-CPU State

```c
struct kmem_cache_cpu {
    void *freelist;         // head freelist (fastpath)
    struct slab *page;      // active slab của CPU này
    struct slab *partial;   // partial list riêng CPU
    ...
};
```

- `freelist`: singly-linked list object free
- `page`: active slab đang dùng
- `partial`: slab dùng dở, giữ lại để tái sử dụng


### 5.3 struct slab - Slab Page

```c
struct slab {
    struct kmem_cache *slab_cache; // cache chủ
    void *freelist;                // freelist chung của slab
    unsigned short inuse;          // số object đang allocated
    unsigned short objects;        // tổng object trong slab
    struct list_head slab_list;    // móc vào partial list
    ...
};
```

- `slab_cache`: thuộc cache nào
- `freelist`: khác với per-CPU freelist, dùng khi slab vào partial list
- `slab_list`: móc vào partial list trên node/CPU


### 5.4 struct kmem_cache_node - Per-NUMA Node

```c
struct kmem_cache_node {
    spinlock_t list_lock;
    struct list_head partial;   // partial slab list (dùng chung)
    ...
};
```

- `partial`: list slab chưa full, dùng khi per-CPU hết object
- Có lock, dùng trong **slowpath**


### 5.5 Đường đi của kmalloc(64) - Fastpath

```
1. CPU 0 gọi kmalloc(64)
2. Tìm cache: kmem_cache = &kmalloc-64
3. Lấy per-CPU state: cpu_slab = kmem_cache->cpu_slab[^0]
4. Check freelist: obj = cpu_slab->freelist
5. Pop: cpu_slab->freelist = obj->next
6. Clear freelist ptr: obj->next = 0
7. Return: &obj (kernel VA)
```


## Phần 6: Kernel Heap Exploitation

### 6.1 Các kiểu bug phổ biến

#### 6.1.1 Heap Overflow

- Tràn từ object A sang object B trong cùng slab[^2][^3][^1]
- **Mục tiêu**:
    - Ghi đè **freelist ptr** của B (nếu B đang free)
    - Ghi đè **field nhạy cảm** trong struct (function pointer, ops, refcount)

**Ví dụ kmalloc-32**:

```
Obj0 (buffer): [AAAA...32B...AAAA][overflow→]
Obj1 (free):   [freelist_ptr→Obj5][...]
               ↑ ghi đè thành &fake_obj
```


#### 6.1.2 Use-After-Free (UAF)

- Struct bị `kfree()` nhưng còn giữ pointer
- **Exploitation**:

1. Free object (vào freelist)
2. Reallocate cùng size bằng kmalloc khác
3. Ghi dữ liệu controlled vào vùng cũ
4. Trigger hành vi dùng pointer cũ → kernel chạy dữ liệu fake


#### 6.1.3 Double Free

- Cùng object `kfree()` hai lần
- Có thể tạo **vòng lặp freelist** hoặc control freelist


#### 6.1.4 Info Leak

- Đọc data từ object vừa kmalloc chưa memset
- Lộ pointer kernel, địa chỉ slab, phá KASLR


### 6.2 Hướng exploit - Freelist Corruption

**Giai đoạn 1: Overflow**

```
A (alloc): [buffer 32B]
B (free):  [next→C][data...]
           ↑ overflow từ A, ghi thành &fake_obj
```

**Giai đoạn 2: Alloc để pop**

```
kmalloc(32) → pop B
freelist_head → C
```

**Giai đoạn 3: Alloc lần nữa**

```
kmalloc(32) → pop C
freelist_head → fake_obj (controlled!)
```

**Giai đoạn 4: Kiểm soát**

```
kmalloc(32) → trả về fake_obj
→ ghi/đọc vào struct nhạy cảm (file_operations, cred,...)
```


### 6.3 UAF với kernel object

**Target thường gặp**: struct chứa function pointer[^3][^1]

- `file_operations`: ioctl, read, write, ...
- `tty_operations`
- `proto_ops` (socket)
- `pipe_buffer_operations`

**Quy trình**:

1. Tạo object kernel (fd, socket, tty, msg_msg, ...)
2. Trigger bug → free nhưng giữ handle
3. Spray kmalloc(size) từ subsystem khác → reclaim
4. Ghi fake vtable/ops/function pointer
5. Trigger callback → RIP control → ROP/ret2usr

## Phần 7: So sánh Userland vs Kernel Heap

| Aspect | ptmalloc (userland) | SLUB (kernel) |
| :-- | :-- | :-- |
| Allocator | ptmalloc/glibc | SLUB |
| Cache layer | tcache bins | kmalloc-X caches |
| Metadata | **Ngoài chunk** | **Trong object** |
| Freelist | Singly/doubly linked | **Singly linked LIFO** |
| Concurrency | Per-thread tcache | **Per-CPU freelist** |
| Overflow impact | Khó chạm metadata | **Dễ ghi freelist ptr** |
| Exploitation | fd/bk, tcache dup | **Freelist corruption, UAF** |
| Protection | Safe-linking, key | Freelist randomization, hardened_usercopy |

## Kết luận

**SLUB kernel heap** khác biệt căn bản với ptmalloc ở chỗ:

1. **Metadata embedded**: freelist ptr nằm trong object → dễ overflow corruption
2. **Per-CPU lockless**: mỗi CPU có freelist riêng → nhanh nhưng có race condition
3. **Fixed-size pools**: slab cache system → dễ dự đoán layout
4. **Kernel context**: exploit target là kernel struct (ops, function ptr, cred) → RCE/privesc

[^1]: https://argp.github.io/2012/01/03/linux-kernel-heap-exploitation/

[^2]: https://duasynt.com/blog/linux-kernel-heap-feng-shui-2022

[^3]: https://blog.lexfo.fr/cve-2017-11176-linux-kernel-exploitation-part3.html

[^4]: Abraham-Silberschatz-Greg-Gagne-Peter-B-Galvin-Operating-System-Concepts-Wiley-2018.pdf

[^5]: William-Stallings-Operating-Systems-1.pdf

[^6]: https://docs.kernel.org/arch/x86/x86_64/mm.html

[^7]: https://docs.kernel.org/6.2/x86/x86_64/mm.html

[^8]: https://stackoverflow.com/questions/46509152/why-in-x86-64-the-virtual-address-are-4-bits-shorter-than-physical-48-bits-vs

[^9]: https://en.wikipedia.org/wiki/X86-64

[^10]: https://docs.kernel.org/mm/page_tables.html

[^11]: https://blogs.oracle.com/linux/linux-slub-allocator-internals-and-debugging-1

[^12]: https://events.static.linuxfound.org/images/stories/pdf/klf2012_kim.pdf

[^13]: https://hammertux.github.io/slab-allocator

[^14]: https://sam4k.com/linternals-memory-allocators-0x02/

