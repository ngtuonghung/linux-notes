## 1. Background: Tại sao cần Filesystem?

Đĩa cứng chỉ hiểu các sector/block vật lý theo số thứ tự (0, 1, 2, 3...), không có khái niệm về "file", "thư mục", hay đường dẫn `/home/user/a.txt`.[^1][^28]

**Filesystem (như ext4) đóng vai trò "lớp trung gian"** giữa hệ điều hành và thiết bị lưu trữ để:

- **Map** từ đường dẫn/tên file → vị trí block vật lý trên đĩa
- **Quản lý metadata**: quyền truy cập, owner, timestamp, kích thước
- **Tổ chức dữ liệu** theo cấu trúc cây thư mục logic
- **Cung cấp cơ chế bảo vệ**: permissions, ACL, journaling, atomic operations

Nếu không có filesystem, mỗi ứng dụng phải tự quản lý block, dễ gây xung đột, mất dữ liệu, và không có cơ chế forensics/recovery.[^2][^1]

***

## 2. EXT4 là gì?

**EXT4 (Fourth Extended Filesystem)** là phiên bản mới nhất của dòng ext, được giới thiệu năm 2008, là filesystem mặc định trên hầu hết các bản phân phối Linux hiện đại.[^3][^28]

**Đặc điểm nổi bật:**

- Hỗ trợ phân vùng lên tới 1 exabyte, file đơn lên tới 16 terabyte
- Sử dụng **extents** thay vì block mapping truyền thống (giảm phân mảnh, tăng hiệu suất file lớn)
- **Journaling** để bảo vệ metadata khi crash/mất điện
- Hỗ trợ **delayed allocation**, **persistent preallocation**
- Backward compatible với ext3/ext2[^1][^3]

***

## 3. Các Thành Phần Cốt Lõi của EXT4

### 3.1. Block

- **Đơn vị lưu trữ nhỏ nhất** mà filesystem quản lý, thường là 4KB (cấu hình được khi tạo filesystem)
- Đĩa được chia thành các block, file chiếm một hoặc nhiều block
- Ví dụ: file 5KB với block size 4KB cần **2 block**[^3][^1]


### 3.2. Block Group

- EXT4 chia partition thành nhiều **block groups**
- Mỗi block group chứa: block bitmap, inode bitmap, inode table, data blocks
- Giúp tối ưu locality, giảm seek time[^1][^3]


### 3.3. Superblock

**Metadata toàn hệ thống**, không phải metadata của từng file:

- Kích thước filesystem, số block, số inode
- Block size, inode size
- Trạng thái filesystem (clean/dirty)
- Các tính năng được bật (journal, extents, 64bit...)
- Vị trí: block đầu tiên của filesystem, có backup copies ở một số block groups[^2][^1]


### 3.4. Inode (Information Node)

**Metadata cho một file/thư mục cụ thể**, mỗi file có một inode duy nhất:

**Nội dung inode:**

- **File mode**: loại file (thường, thư mục, symlink, device...) + quyền rwx
- **Owner**: UID, GID
- **Size**: kích thước file (bytes)
- **Link count**: số directory entry trỏ tới inode này
- **Timestamps**:
    - `atime`: last access time
    - `mtime`: last modification time (nội dung)
    - `ctime`: last change time (metadata)
    - `crtime`: creation/birth time (ext4)
- **Block/Extent map**: thông tin để map offset logic trong file → block vật lý trên đĩa
- **Flags**: immutable, append-only, no-dump...
- **Extended attributes (xattr)**: ACL, SELinux labels, user-defined attributes[^2][^3][^1]

**Lưu ý**: Inode **KHÔNG chứa tên file** – tên file nằm trong directory entry.

### 3.5. Directory Entry

- **Thư mục là một file đặc biệt**, nội dung của nó là danh sách các **directory entry**
- Mỗi entry chứa:
    - **Tên file** (string)
    - **Số inode** tương ứng
- Mỗi thư mục có entry đặc biệt:
    - `"."` → inode của chính thư mục đó
    - `".."` → inode của thư mục cha[^29][^2]


### 3.6. Bitmap

- **Inode bitmap**: đánh dấu inode nào đang dùng, inode nào free
- **Block bitmap**: đánh dấu block nào đang dùng, block nào free
- Dùng khi cấp phát inode/block mới cho file[^3][^1]


### 3.7. Extents

- **Extent = một dãy block liên tục** trên đĩa
- Thay vì lưu từng block riêng lẻ, ext4 lưu: `(logical_offset, physical_start_block, length)`
- Một extent có thể map tới 128 MiB (với block 4KB)
- Giảm metadata overhead, giảm phân mảnh, tăng hiệu suất[^30][^1][^3]

***

## 4. Kiến Trúc Layer: Từ Application xuống Disk

Khi mở file `/home/user/a.txt`, dữ liệu đi qua các layer:

1. **Process / Application**: gọi `open()`, `read()`, `write()`
2. **Libc**: wrapper cho syscall
3. **VFS (Virtual File System)**: layer trừu tượng trong kernel, quản lý file descriptor, open file table, dentry cache, inode cache
4. **EXT4 driver**:
    - Parse đường dẫn qua directory entries
    - Tra cứu inode → extent/block map
    - Quyết định block nào cần đọc/ghi
5. **Page Cache**: cache dữ liệu file trong RAM
6. **Block Layer**: I/O scheduler, request queue, gom/tối ưu các request
7. **Device Driver**: SATA/NVMe/SCSI driver
8. **Storage Device**: SSD/HDD vật lý[^31][^32][^1]

**EXT4 nằm giữa VFS (trên) và Block Layer (dưới).**

***

## 5. Quy Trình Chi Tiết

### 5.1. Mở và Đọc File: `open("/home/user/a.txt", O_RDONLY)` → `read()`

**Bước 1-4: Path resolution (tìm inode của file)**

1. VFS gọi ext4, bắt đầu từ **root inode** (thường là inode số 2)
2. Đọc data blocks của thư mục `/` (chứa directory entries)
3. Tìm entry `"home"` → lấy inode của `/home`
4. Đọc data blocks của `/home`, tìm entry `"user"` → inode `/home/user`
5. Đọc data blocks của `/home/user`, tìm entry `"a.txt"` → **inode của file a.txt**

**Bước 5-8: Lấy metadata và chuẩn bị đọc**
6. Từ inode `a.txt`, ext4 có metadata (size, permissions, timestamps) và **extent/block map**
7. VFS tạo `struct file` (open file object), cấp file descriptor (fd) cho process

**Bước 9-12: Đọc dữ liệu**
8. Khi `read(fd, buf, n)`: VFS gọi `ext4_file_read_iter`
9. EXT4 dùng extent map để biết cần đọc block vật lý nào
10. **Page cache check**:
- Nếu block đã cache trong RAM → copy trực tiếp
- Nếu chưa → yêu cầu block layer đọc từ đĩa vào page cache, rồi copy cho user
11. Cập nhật offset trong struct file, trả số byte đã đọc[^31][^1]

***

### 5.2. Tạo và Ghi File: `open("new.txt", O_CREAT|O_WRONLY)` → `write()`

**Tạo file:**

1. **Cấp phát inode**:
    - Dùng **inode bitmap** tìm inode trống
    - Đánh dấu inode là "used"
    - Ghi metadata cơ bản (owner, mode, time, size=0)
2. **Cập nhật directory entry**:
    - Thêm entry `"new.txt" → inode mới` vào thư mục cha
    - Thư mục cha cũng có inode, nội dung của nó (data blocks) chứa danh sách entry

**Ghi dữ liệu:**
3. Khi `write(fd, "ABC", 3)`:

- **Cấp phát block**: dùng **block bitmap** tìm block trống
- **Cập nhật extent** trong inode: `offset 0-3 → block vật lý B`
- Ghi dữ liệu vào **page cache**, sau đó flush xuống block B trên đĩa
- Cập nhật inode: `size=3`, `mtime`, `ctime`

4. (Tùy mount option) metadata/data changes ghi vào **journal** trước khi commit[^30][^1]

***

### 5.3. Xóa File: `rm a.txt`

1. **Xóa directory entry**:
    - Gỡ bỏ entry `"a.txt" → inode N` khỏi thư mục cha
    - Kết quả: không còn tra được tên → inode
2. **Giải phóng inode**:
    - Đánh dấu inode N là **free** trong inode bitmap
    - Inode có thể được dùng lại cho file khác
3. **Giải phóng data blocks**:
    - Các block mà inode N trỏ tới được đánh dấu **free** trong block bitmap
    - **Dữ liệu cũ vẫn còn trên đĩa** cho đến khi bị ghi đè[^33][^29]

**Ý nghĩa forensics**:

- Tên bị xóa (directory entry), nhưng **inode + block data có thể còn dấu vết**
- Tool forensics có thể quét inode table, tìm inode "free" nhưng chưa bị ghi đè, rồi khôi phục dữ liệu từ các block cũ
- Crash giữa các bước có thể tạo **orphan inode** (inode còn dữ liệu nhưng không có entry nào trỏ tới)[^34][^35]

***

## 6. Page Cache

**Page cache** là vùng **RAM trong kernel** dùng để cache nội dung file theo đơn vị page (thường 4KB).[^32][^36][^31]

**Vai trò:**

- **Đọc**: nếu dữ liệu đã có trong page cache → đọc thẳng từ RAM, không cần truy cập đĩa (rất nhanh)
- **Ghi**: dữ liệu được ghi vào page cache trước (write-back), kernel flush xuống đĩa sau (async hoặc khi `fsync()`)
- Giảm I/O đĩa, tăng throughput, cải thiện latency[^37][^38][^39]

**Liên quan security research:**

- Timing attack: đo thời gian đọc file → biết được file có trong cache không (side-channel)[^40]
- Dữ liệu nhạy cảm có thể nằm lâu trong page cache nếu không flush, dễ bị dump memory[^36]

***

## 7. VFS là gì?

- VFS (Virtual File System) là một lớp trừu tượng trong kernel Linux, ngồi giữa chương trình và các filesystem cụ thể (ext4, xfs, btrfs, FAT32, NFS…).
- Nó cung cấp một bộ API chung (open, read, write, mkdir, …) để:
    - Chương trình chỉ cần dùng một giao diện duy nhất.
    - Kernel có thể “gắn” nhiều loại filesystem khác nhau mà app không cần đổi code.

Nói nôm na: VFS là “lớp adapter” để mọi filesystem trông giống nhau từ góc nhìn chương trình.

[^1]: https://blogs.oracle.com/linux/understanding-ext4-disk-layout-part-1

[^2]: https://opensource.com/article/17/5/introduction-ext4-filesystem

[^3]: https://en.wikipedia.org/wiki/Ext4

[^4]: https://www.youtube.com/watch?v=ej-HXtWMkP8

[^5]: https://www.cs.cmu.edu/~mihaib/fs/fs.html

[^6]: https://nyx.skku.ac.kr/wp-content/uploads/2019/11/12-EXT4-1.pdf

[^7]: https://www.geeksforgeeks.org/linux-unix/linux-file-system/

[^8]: https://docs.kernel.org/admin-guide/ext4.html

[^9]: https://www.linuxjournal.com/content/understanding-linux-filesystems-inodes-block-sizes-and-data-structures

[^10]: https://arxiv.org/abs/2403.06790

[^11]: https://link.springer.com/10.1007/s10586-023-04141-4

[^12]: https://annals-csis.org/Volume_12/drp/535.html

[^13]: https://www.mdpi.com/2079-9292/10/18/2310

[^14]: https://www.semanticscholar.org/paper/05ed3884e31f10b0a7cab8b4f6d00104b6de861e

[^15]: https://ieeexplore.ieee.org/document/9913985/

[^16]: https://link.springer.com/10.1631/FITEE.2200469

[^17]: https://www.semanticscholar.org/paper/8e2af073f377fa4f61efe49ff2722691655dedb5

[^18]: https://journalajrcos.com/index.php/AJRCOS/article/view/212

[^19]: http://ieeexplore.ieee.org/document/7273317/

[^20]: https://arxiv.org/pdf/1903.01955.pdf

[^21]: https://arxiv.org/pdf/1312.1810.pdf

[^22]: https://www.ijfmr.com/papers/2024/3/19648.pdf

[^23]: https://arxiv.org/pdf/2403.06790.pdf

[^24]: https://arxiv.org/pdf/2403.15701.pdf

[^25]: https://arxiv.org/abs/1909.10123v1

[^26]: https://dl.acm.org/doi/pdf/10.1145/3673038.3673123

[^27]: https://arxiv.org/pdf/2011.01024.pdf

[^28]: https://vi.wikipedia.org/wiki/Ext4

[^29]: https://www.studocu.vn/vn/document/truong-dai-hoc-ha-noi/principles-of-operating-systems/tutorial-03-he-thong-tap-tin-linux-ext2-ext3-ext4-xfs/139751124

[^30]: https://blogs.oracle.com/linux/extents-and-extent-allocation-in-ext4

[^31]: https://www.studocu.vn/vn/document/truong-dai-hoc-cong-nghiep-ha-noi/kien-truc-may-tinh/co-che-phan-trang-trong-he-dieu-hanh-linux-toi-uu-bo-nho/147244133

[^32]: https://www.scribd.com/document/805206064/Nghien-cứu-tim-hiểu-về-quản-lý-Bộ-nhớ-trong-trong-HĐH-Linux

[^33]: https://www.reddit.com/r/linux4noobs/comments/6b8p3j/why_is_it_so_slow_to_delete_files_from_an_ext4/

[^34]: https://ieeexplore.ieee.org/document/10527331/

[^35]: https://www.sciencedirect.com/science/article/pii/S1742287612000357

[^36]: https://viblo.asia/p/low-on-memory-XL6lARpp5ek

[^37]: https://cloudfly.vn/blog/huong-dan-cach-kiem-tra-ram-tren-linux-chi-tiet

[^38]: https://nhanhoa.com/tin-tuc/cach-xoa-bo-nho-ram-cache-bo-dem-va-hoan-doi-khong-gian-tren-linux.html

[^39]: https://arxiv.org/pdf/2502.02750.pdf

[^40]: https://arxiv.org/pdf/1901.01161.pdf

[^41]: https://link.springer.com/10.1007/978-3-319-99277-8_6

[^42]: http://arxiv.org/pdf/2401.17618.pdf

[^43]: https://ieeexplore.ieee.org/document/11023337/

[^44]: https://arxiv.org/pdf/2108.13785.pdf

[^45]: https://arxiv.org/pdf/2401.17917.pdf

[^46]: https://arxiv.org/pdf/2411.11017.pdf

[^47]: http://link.springer.com/10.1007/978-3-030-05487-8_2

[^48]: https://www.mdpi.com/1424-8220/23/20/8526/pdf?version=1697546835
