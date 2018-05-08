
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */

#include <ngx_config.h>
#include <ngx_core.h>


#define NGX_SLAB_PAGE_MASK   3
#define NGX_SLAB_PAGE        0
#define NGX_SLAB_BIG         1
#define NGX_SLAB_EXACT       2
#define NGX_SLAB_SMALL       3

#if (NGX_PTR_SIZE == 4)

#define NGX_SLAB_PAGE_FREE   0
#define NGX_SLAB_PAGE_BUSY   0xffffffff
#define NGX_SLAB_PAGE_START  0x80000000

#define NGX_SLAB_SHIFT_MASK  0x0000000f
#define NGX_SLAB_MAP_MASK    0xffff0000
#define NGX_SLAB_MAP_SHIFT   16

#define NGX_SLAB_BUSY        0xffffffff

#else /* (NGX_PTR_SIZE == 8) */

#define NGX_SLAB_PAGE_FREE   0
#define NGX_SLAB_PAGE_BUSY   0xffffffffffffffff
#define NGX_SLAB_PAGE_START  0x8000000000000000

#define NGX_SLAB_SHIFT_MASK  0x000000000000000f
#define NGX_SLAB_MAP_MASK    0xffffffff00000000
#define NGX_SLAB_MAP_SHIFT   32

#define NGX_SLAB_BUSY        0xffffffffffffffff

#endif

//指针偏移到slots数组地址的起始位置，跳过pool的头部管理结构
#define ngx_slab_slots(pool)                                                  \
    (ngx_slab_page_t *) ((u_char *) (pool) + sizeof(ngx_slab_pool_t))

//获取page的低两位存的类型
#define ngx_slab_page_type(page)   ((page)->prev & NGX_SLAB_PAGE_MASK)

#define ngx_slab_page_prev(page)                                              \
    (ngx_slab_page_t *) ((page)->prev & ~NGX_SLAB_PAGE_MASK)

//page在共享内存中的地址
/*
*	(page) - (pool)->pages):page到共享内存中page的偏移量
*	偏移量左移ngx_pagesize_shift:到start的偏移
*	+start:真正的地址
*/
#define ngx_slab_page_addr(pool, page)                                        \
    ((((page) - (pool)->pages) << ngx_pagesize_shift)                         \
     + (uintptr_t) (pool)->start)


#if (NGX_DEBUG_MALLOC)

#define ngx_slab_junk(p, size)     ngx_memset(p, 0xA5, size)

#elif (NGX_HAVE_DEBUG_MALLOC)

#define ngx_slab_junk(p, size)                                                \
    if (ngx_debug_malloc)          ngx_memset(p, 0xA5, size)

#else

#define ngx_slab_junk(p, size)

#endif

static ngx_slab_page_t *ngx_slab_alloc_pages(ngx_slab_pool_t *pool,
    ngx_uint_t pages);
static void ngx_slab_free_pages(ngx_slab_pool_t *pool, ngx_slab_page_t *page,
    ngx_uint_t pages);
static void ngx_slab_error(ngx_slab_pool_t *pool, ngx_uint_t level,
    char *text);


static ngx_uint_t  ngx_slab_max_size;
static ngx_uint_t  ngx_slab_exact_size;
static ngx_uint_t  ngx_slab_exact_shift;


void
ngx_slab_sizes_init(void)
{
    ngx_uint_t  n;

    ngx_slab_max_size = ngx_pagesize / 2;
    ngx_slab_exact_size = ngx_pagesize / (8 * sizeof(uintptr_t));
    for (n = ngx_slab_exact_size; n >>= 1; ngx_slab_exact_shift++) {
        /* void */
    }
}


void
ngx_slab_init(ngx_slab_pool_t *pool)
{
    u_char           *p;
    size_t            size;
    ngx_int_t         m;
    ngx_uint_t        i, n, pages;
    ngx_slab_page_t  *slots, *page;

    pool->min_size = (size_t) 1 << pool->min_shift;

	//跳过pool头部管理结构
    slots = ngx_slab_slots(pool);

    p = (u_char *) slots;
    size = pool->end - p;

    ngx_slab_junk(p, size);//把内存置位0xA5？？？

	/*
	*	计算分级数
	*	eg：若最大页面是4K，则ngx_pagesize_shift=12
	*	n=12-3=9
	*/
    n = ngx_pagesize_shift - pool->min_shift;
	//以页面大小4K为例
	//分0~8级（8,16,32,64,128,256,512,1024,2048）
	//每个分级对应的页内存划分为4096/(2^(i+3))个存储单元,最多可分为512个单元(i=0)，最少2个单元(i=8)
	//slots[0]负责[1,8]区间大小的管理,单元大小8,1页可划分512个单元
	//slots[1]负责[9,16]区间大小的管理,单元大小16,1页可划分256个单元
	//slots[2]负责[17,32]区间大小的管理,单元大小32,1页可划分128个单元
	//slots[3]负责[33,64]区间大小的管理,单元大小64,1页可划分64个单元
	//slots[4]负责[65,128]区间大小的管理,单元大小128,1页可划分32个单元
	//slots[5]负责[129,256]区间大小的管理,单元大小256,1页可划分26个单元
	//slots[6]负责[257,512]区间大小的管理,单元大小512,1页可划分8个单元
	//slots[7]负责[513,1024]区间大小的管理,单元大小1024,1页可划分4个单元
	//slots[8]负责[1025,2048]区间大小的管理,单元大小2048,1页可划分2个单元
	//分级分别使用bitmap来标识哪些单元空闲或正使用

	/*
	*	初始化pool头部结构之后的一篇内存-->slots数组
	*	
	*/
    for (i = 0; i < n; i++) {
        /* only "next" is used in list head */
        slots[i].slab = 0;
		/*
		*	slots数组元素中的next是真正的链头，目前是指向本身的
		*	下次分配内存会将后面某一块空闲page挂载到next的下面
		*/
        slots[i].next = &slots[i]; 
        slots[i].prev = 0;
    }
	//p跳过slots数组这片内存
    p += n * sizeof(ngx_slab_page_t);

	//pool的stats指向slots数组后面的这块指针
    pool->stats = (ngx_slab_stat_t *) p;
	//初始化pool->stats地址开的n个ngx_slab_stat_t结构的内存
    ngx_memzero(pool->stats, n * sizeof(ngx_slab_stat_t));

	//p跳过pool->stats这段内存区域
    p += n * sizeof(ngx_slab_stat_t);

	/*
	*	size的减去slots数组和stats区域
	*/
    size -= n * (sizeof(ngx_slab_page_t) + sizeof(ngx_slab_stat_t));

	/*
	*	将size内存分成pages个页面
	*	每个页面有一个ngx_slab_page_t的额外长度
	*/
    pages = (ngx_uint_t) (size / (ngx_pagesize + sizeof(ngx_slab_page_t)));

	//pool->pages字段指向的是可用内存的起始位置
    pool->pages = (ngx_slab_page_t *) p;
    ngx_memzero(pool->pages, pages * sizeof(ngx_slab_page_t));

    page = pool->pages;

    /* only "next" is used in list head */
    pool->free.slab = 0;
	//和上面的slots数组一样，next是指向空闲page的首地址
    pool->free.next = page;	
    pool->free.prev = 0;

    page->slab = pages;	//空闲page数量
    page->next = &pool->free;	//next指向空闲页的管理指针
    page->prev = (uintptr_t) &pool->free;	//prev还会用来保存其他信息

	/*
	*	start指向对齐后的page页面起始地址
	*	跳过pages个ngx_slab_page_t个内存空间
	*/
    pool->start = ngx_align_ptr(p + pages * sizeof(ngx_slab_page_t),
                                ngx_pagesize);
	/*
	*	m计算对齐后的pages是都存在误差
	*/
    m = pages - (pool->end - pool->start) / ngx_pagesize;
    if (m > 0) {
        pages -= m;
        page->slab = pages;
    }
	
    pool->last = pool->pages + pages;	//最后一块可用page
    pool->pfree = pages;	//空闲的page数量

    pool->log_nomem = 1;
    pool->log_ctx = &pool->zero;
    pool->zero = '\0';
}


void *
ngx_slab_alloc(ngx_slab_pool_t *pool, size_t size)
{
    void  *p;

    ngx_shmtx_lock(&pool->mutex);	//共享内存中分配内存需要加锁

	//执行分配操作
    p = ngx_slab_alloc_locked(pool, size);

    ngx_shmtx_unlock(&pool->mutex);

    return p;
}


/*
*	ngx_slab_alloc_locked:从共享内存中找到一块合适的chunk
*	return:chunk的地址
*/
void *
ngx_slab_alloc_locked(ngx_slab_pool_t *pool, size_t size)
{
    size_t            s;
    uintptr_t         p, m, mask, *bitmap;
    ngx_uint_t        i, n, slot, shift, map;
    ngx_slab_page_t  *page, *prev, *slots;

	/*
	*	若申请的内存大小>ngx_slab_max_size,则直接申请页面
	*/
    if (size > ngx_slab_max_size) {

        ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                       "slab alloc: %uz", size);
		/*
		*	去申请page页
		*	申请页的个数是：
		*	(size >> ngx_pagesize_shift) + ((size % ngx_pagesize) ? 1 : 0))
		*	size>>ngx_pagesize_shift = size/4096-->包含几个页数
		*	(size % ngx_pagesize) ? 1 : 0-->如果不是整除页数的需要best fit
		*	即：多分配一个页来满足
		*/
        page = ngx_slab_alloc_pages(pool, (size >> ngx_pagesize_shift)
                                          + ((size % ngx_pagesize) ? 1 : 0));
		/*
		*	page返回是管理结构的地址
		*	需要做到页地址的转换
		*/
		if (page) {
			
            p = ngx_slab_page_addr(pool, page);

        } else {
            p = 0;
        }

        goto done;
    }
	//大于最小的chunk，则去寻找合适的chunk进行分配
    if (size > pool->min_size) {
        shift = 1;
        for (s = size - 1; s >>= 1; shift++) { /* void */ }
		//slot:对应分级的数组下标，比如8字节--->0
		//shift:size对应的shfit，比如9字节--->4
        slot = shift - pool->min_shift;

	//如果小于最小的chunk则按照最小的chunk分配
    } else {
        shift = pool->min_shift;
        slot = 0;
    }

    pool->stats[slot].reqs++;

    ngx_log_debug2(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                   "slab alloc: %uz slot: %ui", size, slot);
	//跳到slots数组的起始地址
    slots = ngx_slab_slots(pool);
    page = slots[slot].next;  //这个next就是slots链表下挂的page

	/*
	*	这里可以分两种情况
	*	a.slots对应元素下面还没有page：page->next==page
	*	b.slots对应元素下面已经有page：page->next!=page
	*/
    if (page->next != page) {

		/*
		*	shift<ngx_slab_exact_shift
		*	bitmap直接存在page的前几个chunk中
		*/
        if (shift < ngx_slab_exact_shift) {
			
            bitmap = (uintptr_t *) ngx_slab_page_addr(pool, page);
			//需要map个字节来标志这些chunk
            map = (ngx_pagesize >> shift) / (8 * sizeof(uintptr_t));

            for (n = 0; n < map; n++) {
				//因为bitmap会占用前几个chunk
				//这些chunk会被标记为已使用
                if (bitmap[n] != NGX_SLAB_BUSY) {
					/*
					*	bitmap[n]每次&的值
					*	1 2 4 8 16 32
					*	用二进制来表示就是1 10 100 1000 10000....就是找每一个位
					*/
                    for (m = 1, i = 0; m; m <<= 1, i++) {
                        if (bitmap[n] & m) {//定位bitmap中没有使用的chunk位
                            continue;
                        }

                        bitmap[n] |= m;	//bitmap中标记为已使用

						//计算bitmap位标记的chunk的地址
						/*
						*	拆分一下表达式
						*	(n * sizeof(uintptr_t) * 8) * 1 << shift,
						*	1 << shift是chunk的大小，所以整个表达式
						*	表示n个uintptr_t所表示的地址范围
						*	在加上i<<shift就是第n * 8 * sizeof(uintptr_t) + i
						*	个bit对应的chunk的偏移地址
						*/
                        i = (n * 8 * sizeof(uintptr_t) + i) << shift;
						//bitmap就是这个页面的起始地址
						//p指向的是要分配的chunk
                        p = (uintptr_t) bitmap + i;

                        pool->stats[slot].used++;

						/*
						*	进行bitmap的置位
						*/
                        if (bitmap[n] == NGX_SLAB_BUSY) {
                            for (n = n + 1; n < map; n++) {
                                if (bitmap[n] != NGX_SLAB_BUSY) {
                                    goto done;
                                }
                            }
						
                            prev = ngx_slab_page_prev(page);
                            prev->next = page->next;
                            page->next->prev = page->prev;

                            page->next = NULL;
                            page->prev = NGX_SLAB_SMALL;
                        }

                        goto done;
                    }
                }
            }

        } 
		//shift == ngx_slab_exact_shift)
		//page的slab成员存储的是bitmap
		else if (shift == ngx_slab_exact_shift) {

            for (m = 1, i = 0; m; m <<= 1, i++) {
                if (page->slab & m) {
                    continue;
                }

                page->slab |= m;

                if (page->slab == NGX_SLAB_BUSY) {
                    prev = ngx_slab_page_prev(page);
                    prev->next = page->next;
                    page->next->prev = page->prev;

                    page->next = NULL;
                    page->prev = NGX_SLAB_EXACT;
                }

                p = ngx_slab_page_addr(pool, page) + (i << shift);

                pool->stats[slot].used++;

                goto done;
            }

        } 
		/*
		*	page的slab成员存储:
		*	bitmap(高位)，低16位表示其他的信息
		*/	
		else { /* shift > ngx_slab_exact_shift */

            mask = ((uintptr_t) 1 << (ngx_pagesize >> shift)) - 1;
            mask <<= NGX_SLAB_MAP_SHIFT;

            for (m = (uintptr_t) 1 << NGX_SLAB_MAP_SHIFT, i = 0;
                 m & mask;
                 m <<= 1, i++)
            {
                if (page->slab & m) {
                    continue;
                }

                page->slab |= m;

                if ((page->slab & NGX_SLAB_MAP_MASK) == mask) {
                    prev = ngx_slab_page_prev(page);
                    prev->next = page->next;
                    page->next->prev = page->prev;

                    page->next = NULL;
                    page->prev = NGX_SLAB_BIG;
                }

                p = ngx_slab_page_addr(pool, page) + (i << shift);

                pool->stats[slot].used++;

                goto done;
            }
        }

        ngx_slab_error(pool, NGX_LOG_ALERT, "ngx_slab_alloc(): page is busy");
        ngx_debug_point();
    }

	/*
	*	page不够用的情况
	*	1.第一次分配
	*	2.chunk被分配完
	*/
    page = ngx_slab_alloc_pages(pool, 1);

    if (page) {
		//后续的分配和上面基本一致
        if (shift < ngx_slab_exact_shift) {
            bitmap = (uintptr_t *) ngx_slab_page_addr(pool, page);

			/*
			*	ngx_pagesize>>shift = 对应分级所能切分的chunk个数
			*	1<<shift是chunk大小
			*	8表示一个字节为8位
			*	所以这个n表示的是用几个chunk来表示bitmap
			*/
            n = (ngx_pagesize >> shift) / ((1 << shift) * 8);

            if (n == 0) {
                n = 1;
            }

            /* "n" elements for bitmap, plus one requested */

            for (i = 0; i < (n + 1) / (8 * sizeof(uintptr_t)); i++) {
                bitmap[i] = NGX_SLAB_BUSY;
            }

            m = ((uintptr_t) 1 << ((n + 1) % (8 * sizeof(uintptr_t)))) - 1;
            bitmap[i] = m;

            map = (ngx_pagesize >> shift) / (8 * sizeof(uintptr_t));

            for (i = i + 1; i < map; i++) {
                bitmap[i] = 0;
            }

            page->slab = shift;
            page->next = &slots[slot];
            page->prev = (uintptr_t) &slots[slot] | NGX_SLAB_SMALL;

            slots[slot].next = page;

            pool->stats[slot].total += (ngx_pagesize >> shift) - n;

            p = ngx_slab_page_addr(pool, page) + (n << shift);

            pool->stats[slot].used++;

            goto done;

        } else if (shift == ngx_slab_exact_shift) {

            page->slab = 1;
            page->next = &slots[slot];
            page->prev = (uintptr_t) &slots[slot] | NGX_SLAB_EXACT;

            slots[slot].next = page;

            pool->stats[slot].total += 8 * sizeof(uintptr_t);

            p = ngx_slab_page_addr(pool, page);

            pool->stats[slot].used++;

            goto done;

        } else { /* shift > ngx_slab_exact_shift */

            page->slab = ((uintptr_t) 1 << NGX_SLAB_MAP_SHIFT) | shift;
            page->next = &slots[slot];
            page->prev = (uintptr_t) &slots[slot] | NGX_SLAB_BIG;

            slots[slot].next = page;

            pool->stats[slot].total += ngx_pagesize >> shift;

            p = ngx_slab_page_addr(pool, page);

            pool->stats[slot].used++;

            goto done;
        }
    }

    p = 0;

    pool->stats[slot].fails++;

done:

    ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0,
                   "slab alloc: %p", (void *) p);

    return (void *) p;
}


void *
ngx_slab_calloc(ngx_slab_pool_t *pool, size_t size)
{
    void  *p;

    ngx_shmtx_lock(&pool->mutex);

    p = ngx_slab_calloc_locked(pool, size);

    ngx_shmtx_unlock(&pool->mutex);

    return p;
}


void *
ngx_slab_calloc_locked(ngx_slab_pool_t *pool, size_t size)
{
    void  *p;

    p = ngx_slab_alloc_locked(pool, size);
    if (p) {
        ngx_memzero(p, size);
    }

    return p;
}


void
ngx_slab_free(ngx_slab_pool_t *pool, void *p)
{
    ngx_shmtx_lock(&pool->mutex);
    /*
    *   slab释放函数
    */
    ngx_slab_free_locked(pool, p);

    ngx_shmtx_unlock(&pool->mutex);
}


void
ngx_slab_free_locked(ngx_slab_pool_t *pool, void *p)
{
    size_t            size;
    uintptr_t         slab, m, *bitmap;
    ngx_uint_t        i, n, type, slot, shift, map;
    ngx_slab_page_t  *slots, *page;

    ngx_log_debug1(NGX_LOG_DEBUG_ALLOC, ngx_cycle->log, 0, "slab free: %p", p);

	/*
	*	pool->start是共享内存的可用内存起始地址
	*	pool->end结束地址
	*/
    if ((u_char *) p < pool->start || (u_char *) p > pool->end) {
        ngx_slab_error(pool, NGX_LOG_ALERT, "ngx_slab_free(): outside of pool");
        goto fail;
    }
	/*
	*	p-pool->start是在可用内存位置处的偏移
	*	偏移右移page的shift就是slab对应的下标
	*/
    n = ((u_char *) p - pool->start) >> ngx_pagesize_shift;
    page = &pool->pages[n];
    slab = page->slab;
	/*
	*	获取page的低2位  
	*	共享内存的起始地址是4字节对齐的(低2位是0)
	*	所以低2位可以存储slab类型信息
	*/
    type = ngx_slab_page_type(page); 
    switch (type) {
	/*
	*	type是page的低2位来保存的
	*	所有有四种类型
	*	00 01 10 11
	*/
    case NGX_SLAB_SMALL:
		/*
		*	slab的低四位是shift值
		*	获取shift和size
		*/
        shift = slab & NGX_SLAB_SHIFT_MASK;
        size = (size_t) 1 << shift;

		/*
		*	每一个chunk都是2的次幂数
		*	起始地址&块大小-1应该等于0
		*	eg：chunk=8B 假设起始地址是0x00 
		*	那么下一块的地址就是0x08...
		*	所有08 & (8-1) = 0 
		*/
        if ((uintptr_t) p & (size - 1)) {	//判断指针p是否是对齐的
            goto wrong_chunk;
        }
		/*
		*	(uintptr_t) p & (ngx_pagesize - 1)得到的是p在对应页的偏移量
		*	偏移量右移shift是定位p属于第几个块
		*/
        n = ((uintptr_t) p & (ngx_pagesize - 1)) >> shift;	//n是p属于这个页面的第几个块
		/*
		*	m：p所在bitmap中位的掩码
		*	eg：bitmap中0000 1000 对应的掩码就是8
		*/
		m = (uintptr_t) 1 << (n % (8 * sizeof(uintptr_t)));
		n /= 8 * sizeof(uintptr_t);	//n是p在bitmap中的位
		/*
		*	bitmap:p所属内存页的起始地址
		*/
        bitmap = (uintptr_t *)
                             ((uintptr_t) p & ~((uintptr_t) ngx_pagesize - 1));	//就是下对齐操作

        if (bitmap[n] & m) {
			/*
			*	slot是分级对应的数组下标
			*	eg:shift是3，对应的chunk都是2^3=8
			*	对应的solts数组就是slots[0]
			*/
            slot = shift - pool->min_shift;

			//如果page已满，需要把释放的块重新挂载到slots[slot]下方便下次使用
            if (page->next == NULL) {
                slots = ngx_slab_slots(pool);

				//挂载到slots[slot]链
                page->next = slots[slot].next;
                slots[slot].next = page;

                page->prev = (uintptr_t) &slots[slot] | NGX_SLAB_SMALL;
                page->next->prev = (uintptr_t) page | NGX_SLAB_SMALL;
            }
			//将bitmap中的位置0
            bitmap[n] &= ~m;

            n = (ngx_pagesize >> shift) / ((1 << shift) * 8);	//n：前n个chunk用于bitmap

            if (n == 0) {
                n = 1;
            }
			//bitmap标志位清理，已使用的chunk都在bitmao中置1
            i = n / (8 * sizeof(uintptr_t));		
            m = ((uintptr_t) 1 << (n % (8 * sizeof(uintptr_t)))) - 1;

            if (bitmap[i] & ~m) {
                goto done;
            }
			
            map = (ngx_pagesize >> shift) / (8 * sizeof(uintptr_t));

            for (i = i + 1; i < map; i++) {
                if (bitmap[i]) {
                    goto done;
                }
            }

            ngx_slab_free_pages(pool, page, 1);

            pool->stats[slot].total -= (ngx_pagesize >> shift) - n;

            goto done;
        }

        goto chunk_already_free;

    case NGX_SLAB_EXACT:

		/*
		*	m：计算p在bitmap中的掩码
		*	x=(uintptr_t) p & (ngx_pagesize - 1)结果是p对应page的偏移
		*	y=右移ngx_slab_exact_shift，定位p属于第几个块
		*	z=取这个块数的2的幂就是对应的bitmap掩码
		*	eg:y=2,对应于第二个快，则bitmap中就是第三个位0100，z就是4
		*/
        m = (uintptr_t) 1 <<
                (((uintptr_t) p & (ngx_pagesize - 1)) >> ngx_slab_exact_shift);
        size = ngx_slab_exact_size;

		//判断p的合法性
        if ((uintptr_t) p & (size - 1)) {
            goto wrong_chunk;
        }

        if (slab & m) {
            slot = ngx_slab_exact_shift - pool->min_shift;

            if (slab == NGX_SLAB_BUSY) {
                slots = ngx_slab_slots(pool);

                page->next = slots[slot].next;
                slots[slot].next = page;

                page->prev = (uintptr_t) &slots[slot] | NGX_SLAB_EXACT;
                page->next->prev = (uintptr_t) page | NGX_SLAB_EXACT;
            }

            page->slab &= ~m;

            if (page->slab) {
                goto done;
            }

            ngx_slab_free_pages(pool, page, 1);

            pool->stats[slot].total -= 8 * sizeof(uintptr_t);

            goto done;
        }

        goto chunk_already_free;

    case NGX_SLAB_BIG:

        shift = slab & NGX_SLAB_SHIFT_MASK;
        size = (size_t) 1 << shift;

        if ((uintptr_t) p & (size - 1)) {
            goto wrong_chunk;
        }

        m = (uintptr_t) 1 << ((((uintptr_t) p & (ngx_pagesize - 1)) >> shift)
                              + NGX_SLAB_MAP_SHIFT);

        if (slab & m) {
            slot = shift - pool->min_shift;

            if (page->next == NULL) {
                slots = ngx_slab_slots(pool);

                page->next = slots[slot].next;
                slots[slot].next = page;

                page->prev = (uintptr_t) &slots[slot] | NGX_SLAB_BIG;
                page->next->prev = (uintptr_t) page | NGX_SLAB_BIG;
            }

            page->slab &= ~m;

            if (page->slab & NGX_SLAB_MAP_MASK) {
                goto done;
            }

            ngx_slab_free_pages(pool, page, 1);

            pool->stats[slot].total -= ngx_pagesize >> shift;

            goto done;
        }

        goto chunk_already_free;

	//按页分配的slab
    case NGX_SLAB_PAGE:

        if ((uintptr_t) p & (ngx_pagesize - 1)) {
            goto wrong_chunk;
        }

        if (!(slab & NGX_SLAB_PAGE_START)) {
            ngx_slab_error(pool, NGX_LOG_ALERT,
                           "ngx_slab_free(): page is already free");
            goto fail;
        }

        if (slab == NGX_SLAB_PAGE_BUSY) {
            ngx_slab_error(pool, NGX_LOG_ALERT,
                           "ngx_slab_free(): pointer to wrong page");
            goto fail;
        }

        n = ((u_char *) p - pool->start) >> ngx_pagesize_shift;
        size = slab & ~NGX_SLAB_PAGE_START;

        ngx_slab_free_pages(pool, &pool->pages[n], size);

        ngx_slab_junk(p, size << ngx_pagesize_shift);

        return;
    }

    /* not reached */

    return;

done:

    pool->stats[slot].used--;

    ngx_slab_junk(p, size);

    return;

wrong_chunk:

    ngx_slab_error(pool, NGX_LOG_ALERT,
                   "ngx_slab_free(): pointer to wrong chunk");

    goto fail;

chunk_already_free:

    ngx_slab_error(pool, NGX_LOG_ALERT,
                   "ngx_slab_free(): chunk is already free");

fail:

    return;
}

/*
*	ngx_slab_alloc_pages:申请连续pages个页面
*	return:首个页面的管理结构
*/
static ngx_slab_page_t *
ngx_slab_alloc_pages(ngx_slab_pool_t *pool, ngx_uint_t pages)
{
    ngx_slab_page_t  *page, *p;

	/*
	*	遍历所有空闲页
	*/
    for (page = pool->free.next; page != &pool->free; page = page->next) {
		/*
		*	剩余空闲页是否够用
		*/
        if (page->slab >= pages) {

            if (page->slab > pages) {
				/*
				*	page是管理page页面的指针
				*	在共享内存的stats内存后面，是一个数组
				*	对应管理各自的页
				*/
                page[page->slab - 1].prev = (uintptr_t) &page[pages];//???

                page[pages].slab = page->slab - pages;	//当前页后面剩余连续空闲页数

				/*
				*	从页面链表中分离申请的页
				*/
				page[pages].next = page->next;
                page[pages].prev = page->prev;

				/*
				*	重新设置空闲链指针
				*/
                p = (ngx_slab_page_t *) page->prev;
                p->next = &page[pages];
                page->next->prev = (uintptr_t) &page[pages];

            } else {
                p = (ngx_slab_page_t *) page->prev;
                p->next = page->next;
                page->next->prev = page->prev;
            }
			
            page->slab = pages | NGX_SLAB_PAGE_START;
            page->next = NULL;
            page->prev = NGX_SLAB_PAGE;

            pool->pfree -= pages;

            if (--pages == 0) {
                return page;
            }

			/*
			*	将申请到的页进行标记
			*/
            for (p = page + 1; pages; pages--) {
                p->slab = NGX_SLAB_PAGE_BUSY;
                p->next = NULL;
                p->prev = NGX_SLAB_PAGE;
                p++;
            }
			//page是首个页面管理指针的地址
            return page;
        }
    }

    if (pool->log_nomem) {
        ngx_slab_error(pool, NGX_LOG_CRIT,
                       "ngx_slab_alloc() failed: no memory");
    }

    return NULL;
}


/*
*	释放连续pages个page页
*/
static void
ngx_slab_free_pages(ngx_slab_pool_t *pool, ngx_slab_page_t *page,
    ngx_uint_t pages)
{
    ngx_slab_page_t  *prev, *join;

	//增加空闲页的计数
    pool->pfree += pages;

    page->slab = pages--;

    if (pages) {
        ngx_memzero(&page[1], pages * sizeof(ngx_slab_page_t));
    }

    if (page->next) {
        prev = ngx_slab_page_prev(page);
        prev->next = page->next;
        page->next->prev = page->prev;
    }

    join = page + page->slab;

    if (join < pool->last) {

        if (ngx_slab_page_type(join) == NGX_SLAB_PAGE) {

            if (join->next != NULL) {
                pages += join->slab;
                page->slab += join->slab;

                prev = ngx_slab_page_prev(join);
                prev->next = join->next;
                join->next->prev = join->prev;

                join->slab = NGX_SLAB_PAGE_FREE;
                join->next = NULL;
                join->prev = NGX_SLAB_PAGE;
            }
        }
    }

    if (page > pool->pages) {
        join = page - 1;

        if (ngx_slab_page_type(join) == NGX_SLAB_PAGE) {

            if (join->slab == NGX_SLAB_PAGE_FREE) {
                join = ngx_slab_page_prev(join);
            }

            if (join->next != NULL) {
                pages += join->slab;
                join->slab += page->slab;

                prev = ngx_slab_page_prev(join);
                prev->next = join->next;
                join->next->prev = join->prev;

                page->slab = NGX_SLAB_PAGE_FREE;
                page->next = NULL;
                page->prev = NGX_SLAB_PAGE;

                page = join;
            }
        }
    }

    if (pages) {
        page[pages].prev = (uintptr_t) page;
    }

    page->prev = (uintptr_t) &pool->free;
    page->next = pool->free.next;

    page->next->prev = (uintptr_t) page;

    pool->free.next = page;
}


static void
ngx_slab_error(ngx_slab_pool_t *pool, ngx_uint_t level, char *text)
{
    ngx_log_error(level, ngx_cycle->log, 0, "%s%s", text, pool->log_ctx);
}
