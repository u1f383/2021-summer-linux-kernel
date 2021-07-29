## 測驗 α

```
LLL = (v >> (mask ^ c))
RRR = (v << (mask ^ c))
```

#### 1. 舉出 Linux 核心原始程式碼裡頭 bit rotation 的案例並說明

TODO.

#### 2. x86_64 指令集具備 rotr 和 rotl 指令，上述 C 程式碼經過編譯器最佳化 (例如使用 gcc) 後，能否運用到這二個指令呢？

TODO.



## 測驗 β

```
(sz + mask) & ~mask
```

#### 1. 說明上述程式碼的運作原理

可以分成兩種情況來分析:

-  `(sz & mask) == 0`: alignment 不影響
-  `(sz & mask) != 0`: alignment 影響

我們把 `alignment` 對應到的 bit 稱做 `alignment bit`，當 `(sz + mask)` 在第一種情況 `(sz & mask) == 0`，由於 `mask` 對應到的 bits 不會進位，因此 `((sz + mask) & ~mask) == (sz & ~mask) == sz`，也就是已經 alignment。而在第二種情況 `(sz & mask) != 0`，由於 `(sz & mask) + mask >= alignment`，因此 `alignment bit` 會進位，並且因為 `(sz & mask) + mask <= alignment * 2 - 2`，至多只會讓 `alignment bit` + 1，所以 `((sz + mask) & ~mask) == ((sz + alignment) & ~mask)`，代表 `sz` 已經 alignment。

#### 2. 在 Linux 核心原始程式碼找出類似 align_up 的程式碼，並舉例說明其用法

TODO.



## 測驗 γ

```
12
```

#### 1. 解釋上述程式碼輸出 `-` 字元數量的原理

linux 一共有三種 buffer type:

- ` _IONBF`: unbuffered
- `_IOLBF`: line buffered
- `_IOFBF`: fully buffered

而預設的 fd type 為:

- `stdin`: `_IOLBF`
- `stdout`: `_IOLBF`
- `stderr`: `_IONBF`

因此執行 `fork()` 前，parent 的 I/O buffer 仍有還沒印出的 `-`，因此 child 再 `fork()` 後也會繼承 parent 的 IO buffer，也導致不但最初的 parent process 能在最後印出迴圈數個 `-`，之後的每個 child 也因此都能印出迴圈數個 `-`。

程式碼所能印出的 `-` 數量為: `NNN * pow(2, NNN)`，因此 `NNN * pow(2, NNN) == 49152` 求得 `NNN == 12`。



## 測驗 δ

```
AAA = queue->last->next = node;
BBB = node->value
CCC = queue->first = new_header;
```



#### 1. 解釋上述程式碼運作原理並指出實作缺失

程式在一開始會透過 `con_init()` 來建立 concurrent queue `queue`，而 `con_init()` 主要是為 `queue` 的 struct member 建立一塊空間存放對應的資料。之後程式會建立 4 個 threads，每個 thread 都會把 `0 ~ 1000000-1` 的整數透過 `con_push()` push 進 `queue` 之中，而 `con_push()` 會根據傳入的整數建立一個 `node`，將 `node` 以 update linked list 的方式加到 `queue` 之中，並且在更新 `queue->last `以及 `queue->last->next` 時，會用 `last->mutex` lock 起來，避免 race condition。

之後還會建立 4 個 threads，透過 `pop_thread()` 來 retrieve queue，`pop_thread()` 會不斷的使用 `con_pop()` 得到 `node->value` pointer 並且 `free()` 掉，直到 `value` 的值為 -1 才會離開 infinite loop，`con_pop()` 會取得 `queue` 的第一個 `node`，`con_pop()` 會把更新 `queue` linked list 以及取得 `node->value` 的過程用 mutex lock 保護，不過 `free(node)` 並沒有在 mutex 的保護範圍。

在結束 push threads 以及 pop threads 的建立後，程式會用 `thrd_join()` 先回收 push threads，再用 push 整數 -1 的方式來中斷 pop threads 的 infinite loop，最後用 `thrd_join()` 來回收 pop threads，清空 queue 後結束。

而實作的部分似乎有些沒有注意到的地方:

- `con_init()` 會在失敗時回傳 `NULL`，不過在 `main()` 中並沒有針對回傳的結果做確認
  - 應該需要在一開始舊判斷 `con_init()` 是否成功，如果沒有成功就直接 return
- `con_pop()` 在 `queue->first->next` 為 `NULL` 的時候就回傳 `NULL`，代表 `queue` 中還有一個 element 沒辦法被 pop，導致最後 `thrd_join()` pop threads 時沒辦法 pop 出最後一個 -1，造成一個 thread 被 block 在 infinite loop。這邊不確定原本的設計是否一開始 `con_init()` 時所的 `dummy` 必須留在 `queue` 中，因此這邊分成兩個 case 來討論:
  - `dummy` 應該要留在 `queue` 中: 這樣在 `con_queue_t` 在設計上需要避免 `con_pop()` 將 `dummy` pop 出去，並且要實作使用 `dummy` 判斷 `queue` 是否為 empty 的功能
  - `dummy` 不需要留在 `queue` 中: 這樣在執行 `_con_node_init()` 前可能就要考慮 `queue` 完全沒有 element 的情況，並針對 empty `queue` 的 push pop operation 做一些額外的檢查

#### 2. 以 lock-free 程式設計 改寫上述程式碼

TODO.



## 測驗 ϵ

```
XXX = x + 1
YYY = *ip = mp->hs[i];
```

#### 1. 解釋上述程式碼運作原理

`mpool` 為 memory pool 在程式中的資料結構，各個 member 功能大致如下:

- `cnt`: 當前 pool 的個數，當某個 size 的 pool 滿了而建立新的 pool 時 `cnt` 就會 +1
- `pal`: pool array length，最多總共能有多少 memory pool
- `min_pool`、`max_pool`: 分別是最小的 pool size 以及最大的 pool size
- `ps`: pool pointer，指向目前對應 size 正在使用的 pool，當對應 size 的 pool 用完而建立新的 pool 時就會更新 `ps`
- `sizes`: 紀錄 pool array 中所對應到 pool 的 size
- `hs`: 每個對應 size pool 的頭，紀錄當前分配到哪個 memory chunk

程式一開始透過 `mpool_init()` 建立一個 memory poll `mp`，根據傳入的 `min2` 以及 `max2`為 4 與 11，`cnt` 為 8，`palen` 為 7，`min_pool` 與 `max_pool` 分別為 `2^4` 以及 `2^11`，而後就根據這些值去建立對應大小的空間給其他 member，像是 `pools` 與 `mp` 等等，最後使用 `memset()` 將分配到的空間清乾淨。回到 `main()` 後，會使用 `srandom()` 來設定 PRNG 的 seed，並且使用 ASLR 隨機記憶體 layout 與 pid 每次都不一樣的特性，兩者 xor 的結果 `getpid() ^ &main` 當作 seed。

而後會開始使用 `random()` 來產生隨機的 memory chunk size，大多的情況下大小會落在 0~63，而有 1% 的機率會取得 0~9999 大小的 memory chunk size，最後避免 `random()` 的結果為 0，確保 `size >= 1`。

之後會透過 `mpool_alloc()` 與剛剛產生的 `size` 來建立 memory chunk，`mpool_alloc()` 會先看傳入的 `size` 是否超過 `mp->max_pool`，如果超過就用 `get_mmap()` 來建立 memory chunk 並回傳，如果沒有的話，就會從 `min_pool` 大小開始找，看與 `size` 最接近的 pool size 為多少，並存在 `szceil` 之中，之後會取得對應的大小的 pool head `mp->hs[i]` ，並且透過判斷 `head != NULL` 來確定是否已經建立 pool，沒有的話就使用 `mpool_new_pool()` 建立一個新的。

`mpool_new_pool()` 接收兩個參數 `size` 以及 `total_sz`，大致是拿大小為 `size` 的 chunk 填滿整個 `total_sz` 的空間，並且每個 memory chunk 一開始都是放下一個 chunk 的位置。

回到 `mpool_alloc()`，確定對應到的大小有 pool 後，會有兩種情況:

- pool 已經被使用完畢: 建立新的 pool，並使用 `add_pool()` ，當 extend 當前的 pool array length
- pool 還有 memory chunk 可以使用: 更新 `mp->hs[i]` 為下一個 memory chunk 的位置後，回傳 memory chunk pointer

最後 `mpool_alloc()` 會回傳大小為 `size` 的 memory chunk。

`main()` 接收到回傳得 memory chunk pointer 後，有 1/10 的機率會執行 `mpool_repool()`，即是把使用完畢的 memory chunk 放回 pool 當中，如果大小超過 `mp->max_pool`，則因為一開始是使用 `mmap()` 建立 memory chunk，因此 repool 指需要 `munmap()` 即可。

#### 2. 提出效能和功能的改進策略，並予以實作

TODO.



## 測驗 ζ

```
III = {target_fd, POLLIN}
JJJ = {cl_fd, POLLIN}
```

#### 1. 解釋上述程式碼運作原理

程式從 command line 接收兩個參數，分別是 `target IP address` 以及 `target port`，而 `main()` 的前半部分就是在設置 socket，proxy 的 port 預設開在 1922，並且因為 `htonl(INADDR_ANY)` 的關係，所以主機對外的不同 ip 都可以接收到，之後透過 `bind()` 與 `listen()` 來等待其他 process 連線。

當其他 process 成功連線時，`accept()` 會回傳一個 socket fd，此時程式會透過 `connect_to()` 跟 `target_IP` 以及 `target_Port` 做連線，並且在連線後，透過 `proxy()` 處理 packet forwarding。

`proxy()` 本身接收兩個參數，分別是 `cl_fd` 以及 `target_fd`，而 `proxy()` 會先建立一組 pipe `fds` 以及 `polls`，並且 call `poll()` 等待 file event 的發生，當 `poll()` 回傳時，會有三種可能的回傳值: 0 (syscall timeout)、非負整數 (event 的個數) 以及 -1 (發生錯誤)。

對於 `cl_fd` 以及 `target_fd`，當 `POLLIN` 發生時會讓 `poll()` return，並且從其中一方的 `revents` 就能知道是哪一方發生 `POLLIN`，再透過 `move()` 將資料從寫進來的一方，轉送到另外一方。然而原本的程式並沒有考慮到 `splice()` 回傳 0 代表 End of Input，因此執行 `splice(pip[0], NULL, out_fd, NULL, 8, SPLICE_F_MOVE);` 會 hang up，解決方法為在第一次執行 `splice(in_fd, NULL, pip[1], NULL, 8, SPLICE_F_MOVE)` 時判斷回傳結果是否為 0，如果為 0 代表 EOI，return:

```c
...
	int ret = splice(in_fd, NULL, pip[1], NULL, 8, SPLICE_F_MOVE);
    if (ret == -1) {
        perror("splice(1)");
        return;
    }
    
    if (ret == 0)
        return;
...
```

#### 2. 以 epoll 系統呼叫改寫程式碼，並設計實驗來驗證 proxy 程式碼的效率

TODO.