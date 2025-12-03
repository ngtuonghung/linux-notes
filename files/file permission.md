## Phần 1: Permission cơ bản (DAC - Discretionary Access Control)

### 1.1. Cấu trúc permission cơ bản

Khi chạy `ls -l`, bạn thấy:

```bash
-rw-r--r--  1 alice dev  1234 Dec  3  file.txt
drwxr-x---  2 bob   ops  4096 Dec  3  mydir
```

**10 ký tự đầu tiên** quan trọng nhất:

- **Ký tự 1**: loại object
    - `-` = file thường
    - `d` = directory (thư mục)
    - `l` = symbolic link
- **9 ký tự sau**: chia thành 3 nhóm (mỗi nhóm 3 ký tự):

1. **User (owner)**: quyền của người sở hữu
2. **Group**: quyền của nhóm sở hữu
3. **Others**: quyền của mọi người khác

Mỗi nhóm gồm:

- `r` (read) = 4
- `w` (write) = 2
- `x` (execute) = 1
- `-` = không có quyền đó


### 1.2. Dạng số (Octal notation)

Permission có thể viết dạng số:

- `rw-` = 4+2 = 6
- `r-x` = 4+1 = 5
- `rwx` = 4+2+1 = 7
- `---` = 0

Ví dụ:

- `rw-r--r--` = **644** (owner: rw, group: r, others: r)
- `rwxr-xr-x` = **755** (owner: rwx, group: rx, others: rx)
- `rwx------` = **700** (chỉ owner có full quyền)

Lệnh:

```bash
chmod 644 file.txt
chmod 755 script.sh
```


### 1.3. Khác nhau quan trọng: rwx trên File vs Folder

Đây là điểm mấu chốt mà nhiều người nhầm:

**Với FILE:**

- `r`: đọc nội dung file
- `w`: sửa/xóa nội dung file
- `x`: thực thi file như chương trình/script

**Với FOLDER:**

- `r`: **liệt kê tên** file trong thư mục (`ls` được)
- `w`: **tạo/xóa/đổi tên** file trong thư mục
- `x`: **bước vào thư mục** (traverse/access) - cần để `cd`, để mở file bên trong

**Tình huống đặc biệt:**

- Có `x` mà không có `r` trên folder: bạn truy cập file nếu biết tên chính xác, nhưng không `ls` được danh sách.
- Có `r` mà không có `x`: bạn `ls` thấy tên file nhưng không vào được để đọc.

***

## Phần 2: Permission đặc biệt (SUID, SGID, Sticky Bit)

### 2.1. SUID (Set User ID)

**Khái niệm:** File thực thi có SUID sẽ chạy với **UID của owner file**, không phải UID của người chạy.[^8]

**Cách nhận biết:** Chữ `s` thay `x` ở vị trí owner:

```bash
-rwsr-xr-x 1 root root /usr/bin/passwd
```

**Ý nghĩa security:**

- Nếu binary **root-owned** có SUID + bug (buffer overflow, command injection, path traversal), attacker có thể leo thang lên root.
- Pattern hay gặp: tìm SUID root binary, phân tích có thể chạy shell không.

**Lệnh set:**

```bash
chmod u+s file
chmod 4755 file  # bit 4xxx = SUID
```


### 2.2. SGID (Set Group ID)

**Trên file:** chạy với **GID của group owner**.[^8]

**Trên directory:** file mới tạo trong dir đó **thừa kế group** của dir (không phải group của user tạo).[^8]

**Cách nhận biết:** Chữ `s` ở vị trí group:

```bash
drwxr-sr-x 2 alice dev shared/
```

**Lệnh set:**

```bash
chmod g+s dir
chmod 2755 dir  # bit 2xxx = SGID
```


### 2.3. Sticky Bit

**Chỉ dùng trên directory:** User chỉ xóa được file **của chính mình** trong dir đó (hoặc owner của dir, hoặc root).[^9][^8]

**Ví dụ điển hình:** `/tmp`

```bash
drwxrwxrwt 10 root root /tmp
```

Chữ `t` ở cuối (`others` position).

**Ý nghĩa:** Ngăn user xóa file của người khác trong shared directory.

**Lệnh set:**

```bash
chmod +t dir
chmod 1777 dir  # bit 1xxx = sticky
```


***

## Phần 3: Nơi lưu trữ permission

### 3.1. Inode và mode bits

Toàn bộ permission (rwx + SUID/SGID/sticky) được lưu trong **mode bits** của **inode** của file/thư mục.

- Mỗi file/dir có 1 inode (data structure trong filesystem).
- Inode chứa metadata: owner UID/GID, permission, timestamps, vị trí data blocks.
- Mode bits: 16 bit, trong đó:
    - 4 bit đầu: loại file
    - 3 bit đặc biệt: SUID/SGID/sticky
    - 9 bit cuối: rwx cho user/group/other

Khi chạy `chmod`, kernel chỉ sửa mode bits trong inode, không động vào nội dung file.

### 3.2. Extended attributes (xattr)

- ACL, file capabilities được lưu trong **extended attributes** (xattr) của file.
- Namespace: `security.capability`, `system.posix_acl_access`, v.v.

***

## Phần 4: Khi nào permission bị "bỏ qua" hoặc không quyết định

### 4.1. Root (UID 0)

- User root có **đặc quyền trong kernel**: gần như bỏ qua kiểm tra `rwx` thông thường.
- Root có thể:
    - Đọc hầu hết file
    - Vào hầu hết thư mục
    - `chmod`, `chown` tùy ý

⇒ Nếu đã lên root (hoặc process chạy UID=0), file permission cơ bản không cứu được.

### 4.2. Linux Capabilities

**Ý tưởng:** Chia nhỏ quyền root thành nhiều "mảnh" độc lập.[^10][^11]

**Một số capabilities quan trọng:**

- `CAP_DAC_OVERRIDE`: bỏ qua kiểm tra read/write/execute.[^10]
- `CAP_DAC_READ_SEARCH`: bỏ qua kiểm tra read file và read/execute dir.[^10]
- `CAP_CHOWN`: đổi owner file.
- `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, v.v.

**File capabilities:** gắn vào binary như extended attribute:

```bash
# Xem capabilities của binary
getcap /usr/bin/tar

# Gán capability
sudo setcap cap_dac_read_search+ep /usr/bin/tar
```

**Nguy hiểm:** Nếu binary có capability mạnh (ví dụ `CAP_DAC_READ_SEARCH`), user thường chạy nó có thể đọc file nhạy cảm (ví dụ `/etc/shadow`) dù không có quyền đọc bình thường.[^11][^12]

**Liệt kê capabilities trên hệ thống:**

```bash
getcap -r / 2>/dev/null
```


### 4.3. ACL (Access Control List)

**Khái niệm:** Mở rộng DAC, cho phép gán quyền chi tiết cho **nhiều user/group riêng lẻ** trên cùng 1 file/dir.

**Ví dụ:**

```bash
# File thuộc alice:dev, permission 640
-rw-r----- 1 alice dev secret.txt

# Thêm quyền cho bob (read) và teamtest (rw)
setfacl -m u:bob:r secret.txt
setfacl -m g:teamtest:rw secret.txt

# Xem ACL
getfacl secret.txt
# user:bob:r--
# group:teamtest:rw-
```

**Security note:** `ls -l` không hiển thị ACL đầy đủ. Phải dùng `getfacl` để audit.

### 4.4. MAC (Mandatory Access Control): SELinux và AppArmor

**DAC (rwx) vs MAC:**

- **DAC (Discretionary Access Control)**: owner quyết định ai được truy cập (model `rwx` chuẩn).[^1][^2]
- **MAC (Mandatory Access Control)**: chính sách trung tâm bắt buộc, kể cả root không tự ý nới được.[^2][^1]

**Quy trình check:**

1. DAC check trước (rwx, ACL)
2. Nếu DAC cho phép → MAC check tiếp
3. Nếu MAC cấm → vẫn bị chặn, dù DAC cho phép

#### SELinux – label-based

- Mỗi process, file, socket, port có **context/label** (dạng `user:role:type:level`).
- Policy định nghĩa: "type A được làm gì với type B".
- Rất chi tiết, phức tạp, hợp môi trường high-security.[^13]

Ví dụ:

- File `/etc/shadow` có type `shadow_t`.
- Process web server có type `httpd_t`.
- Policy: `httpd_t` không được đọc `shadow_t`.
- Dù root `chmod 644 /etc/shadow`, web server vẫn bị SELinux chặn.

**Xem context:**

```bash
ls -Z
ps -Z
getenforce  # Enforcing/Permissive/Disabled
```


#### AppArmor – path-based

- Profile định nghĩa **path** mà program được truy cập (không dùng label).[^13]
- Dễ config hơn SELinux, nhưng kém chi tiết.
- Mặc định trên Ubuntu/Debian.

Ví dụ profile:

```
/usr/bin/backup {
  /etc/backup/** r,
  /var/log/backup/** rw,
  deny /etc/shadow r,
}
```

**Xem trạng thái:**

```bash
aa-status
```

**So sánh ngắn gọn:**

- **SELinux**: label-based, cực chi tiết, khó.
- **AppArmor**: path-based, dễ hơn, ít "deep" hơn.


### 4.5. Mount options

Filesystem mount với option đặc biệt có thể vô hiệu hóa quyền:

- `noexec`: cấm thực thi binary/script trên filesystem đó (dù có `x`).
- `ro` (read-only): cấm ghi (dù có `w`).
- `nosuid`: vô hiệu SUID/SGID bit.

***

## Phần 5: Liên hệ Security Research

### 5.1. Pattern privilege escalation thường gặp

**1. SUID root binary có bug:**

- Tìm: `find / -perm -4000 2>/dev/null`
- Kiểm tra: binary có chạy shell, gọi external command không an toàn, path traversal, v.v.
- Ví dụ: binary gọi `system("ls")` mà không dùng full path → hijack PATH.

**2. World-writable file/directory:**

- Tìm: `find / -perm -002 2>/dev/null`
- Script root chạy file world-writable → inject code.
- SGID directory với misconfiguration.

**3. Capabilities misconfiguration:**

- `getcap -r / 2>/dev/null`
- Tìm binary có `CAP_DAC_READ_SEARCH`, `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`.
- Ví dụ: `tar` có `cap_dac_read_search+ep` → đọc được `/etc/shadow`.

**4. Sudoers misconfiguration:**

- `sudo -l`
- Tìm lệnh cho phép chạy không cần password, có thể spawn shell.

**5. ACL ẩn:**

- `getfacl -R /sensitive/path`
- Tìm ACL cho phép user không ngờ tới.

**6. SELinux/AppArmor disabled hoặc permissive:**

- `getenforce` → nếu Permissive/Disabled, exploit dễ hơn.
- `aa-status` → profile bị disable.


### 5.2. Checklist audit permission

```bash
# 1. Xem user hiện tại
id
groups

# 2. Tìm SUID/SGID binary
find / -perm -4000 2>/dev/null  # SUID
find / -perm -2000 2>/dev/null  # SGID

# 3. Tìm file/dir world-writable
find / -perm -002 -type f 2>/dev/null
find / -perm -002 -type d 2>/dev/null

# 4. Tìm capabilities
getcap -r / 2>/dev/null

# 5. Check sudo
sudo -l

# 6. Check MAC
getenforce      # SELinux
aa-status       # AppArmor

# 7. Check mount options
mount | grep -E 'nosuid|noexec'
```

[^1]: https://www.zuar.com/blog/discretionary-access-control-vs-mandatory-access-control/

[^2]: https://docs.oracle.com/en/operating-systems/oracle-linux/6/porting/section_jsf_zpm_wm.html

[^3]: https://www.geeksforgeeks.org/computer-networks/difference-between-dac-and-mac/

[^4]: https://www.permit.io/blog/mac-vs-dac-comparing-access-control-fundamentals

[^5]: https://www.syteca.com/en/blog/mac-vs-dac

[^6]: https://www.portnox.com/cybersecurity-101/what-is-discretionary-access-control/

[^7]: https://richard-sebos.github.io/sebostechnology/posts/DAC-ACL-MAC/

[^8]: https://www.redhat.com/en/blog/suid-sgid-sticky-bit

[^9]: https://notes.kodekloud.com/docs/Linux-System-Administration-for-Beginners/Essential-Commands/SUID-SGID-and-Sticky-Bit

[^10]: https://man7.org/linux/man-pages/man7/capabilities.7.html

[^11]: https://www.hackingarticles.in/linux-privilege-escalation-using-capabilities/

[^12]: https://www.elastic.co/de/security-labs/unlocking-power-safely-privilege-escalation-via-linux-process-capabilities

[^13]: https://tuxcare.com/blog/selinux-vs-apparmor/

