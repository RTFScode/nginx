
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_SLAB_H_INCLUDED_
#define _NGX_SLAB_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_slab_page_s  ngx_slab_page_t;

/*
*	ngx_slab_page_t:共享内存中分配页的管理结构
*/
struct ngx_slab_page_s {
	/*
	*	slab表示的值可分为以下几种
	*	a. pages的数量(slab,page管理结构)
	*	b. 页面的chunk的使用情况的bitmap(shift == ngx_slab_exact_shift)
	*	c. chunk大小的移位，即shift(低4位)(shift < ngx_slab_exact_shift)
	*	d. shift(低4位)，bitmap(高16位)(shift > ngx_slab_exact_shift)
	*/
    uintptr_t         slab;	
    ngx_slab_page_t  *next;	//这个管理结构是一个双向链表

	//用低3bit表示分配类型(NGX_SLAB_PAGE,NGX_SLAB_BIG,NGX_SLAB_EXACT,NGX_SLAB_SMALL)
    uintptr_t         prev;	
};

/*
*	ngx_slab_stat_t:slab的状态管理结构
*	这个管理page是page已经挂载到slots对应分级的数组下面
*/
typedef struct {
    ngx_uint_t        total;	//page中可用的chunk总数
    ngx_uint_t        used;		//已使用的chunk数

    ngx_uint_t        reqs;		//当前页面在在分配chunk是被引用的次数
    ngx_uint_t        fails;	//分配失败的次数
} ngx_slab_stat_t;

/*
*	ngx_slab_pool_t:ngx共享内存的管理结构
*/
typedef struct {
    ngx_shmtx_sh_t    lock;	

    size_t            min_size;	//最小分级字节数	8字节
    size_t            min_shift;//最小分级对应移位数	3-->2^3=8

    ngx_slab_page_t  *pages;	//内存分配页管理数组
    ngx_slab_page_t  *last;		//内存分配页最后一个页
    ngx_slab_page_t   free;		//空闲页链表

    ngx_slab_stat_t  *stats;	//页分配状态管理数组
    ngx_uint_t        pfree;

    u_char           *start;	//可分配内存的起始地址
    u_char           *end;		//可分配内存的结束地址

    ngx_shmtx_t       mutex;	

    u_char           *log_ctx;
    u_char            zero;

    unsigned          log_nomem:1;

    void             *data;
    void             *addr;
} ngx_slab_pool_t;


void ngx_slab_sizes_init(void);
void ngx_slab_init(ngx_slab_pool_t *pool);
void *ngx_slab_alloc(ngx_slab_pool_t *pool, size_t size);
void *ngx_slab_alloc_locked(ngx_slab_pool_t *pool, size_t size);
void *ngx_slab_calloc(ngx_slab_pool_t *pool, size_t size);
void *ngx_slab_calloc_locked(ngx_slab_pool_t *pool, size_t size);
void ngx_slab_free(ngx_slab_pool_t *pool, void *p);
void ngx_slab_free_locked(ngx_slab_pool_t *pool, void *p);


#endif /* _NGX_SLAB_H_INCLUDED_ */
