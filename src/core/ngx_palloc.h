
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_PALLOC_H_INCLUDED_
#define _NGX_PALLOC_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/*
 * NGX_MAX_ALLOC_FROM_POOL should be (ngx_pagesize - 1), i.e. 4095 on x86.
 * On Windows NT it decreases a number of locked pages in a kernel.
 */
#define NGX_MAX_ALLOC_FROM_POOL  (ngx_pagesize - 1)

#define NGX_DEFAULT_POOL_SIZE    (16 * 1024)

#define NGX_POOL_ALIGNMENT       16
#define NGX_MIN_POOL_SIZE                                                     \
    ngx_align((sizeof(ngx_pool_t) + 2 * sizeof(ngx_pool_large_t)),            \
              NGX_POOL_ALIGNMENT)


typedef void (*ngx_pool_cleanup_pt)(void *data);

typedef struct ngx_pool_cleanup_s  ngx_pool_cleanup_t;
/*
*	内存池回收结构
*/
struct ngx_pool_cleanup_s {
    ngx_pool_cleanup_pt   handler;	//清理函数
    void                 *data;		//需要清理的内存地址
    ngx_pool_cleanup_t   *next;		//下一个清理结构
};


typedef struct ngx_pool_large_s  ngx_pool_large_t;
/*
*	大块页的数据结构
*/
struct ngx_pool_large_s {
    ngx_pool_large_t     *next;		//指向下一个存储地址
    void                 *alloc;	//指向数据块的指针
};

/*
*	内存池内存的管理指针
*/
typedef struct {
    u_char               *last;		//指向内存池跳过pool结构的位置
    u_char               *end;		//指向内存池的结束地址
    ngx_pool_t           *next;		//下一个内存池
    ngx_uint_t            failed;	//分配失败次数的记录
} ngx_pool_data_t;

/*
*	内存池管理结构
*/
struct ngx_pool_s {
    ngx_pool_data_t       d; //指向内存池的data部分	
    //下面的成员都是内存池根节点的特有成员
    size_t                max;		//内存池最大可分配内存的大小
    ngx_pool_t           *current;	//指向当前的内存池指针地址
    ngx_chain_t          *chain;	//缓冲区链表
    ngx_pool_large_t     *large;	//large块的链表
    ngx_pool_cleanup_t   *cleanup;	//清理结构
    ngx_log_t            *log;		//日志接口
};


typedef struct {
    ngx_fd_t              fd;
    u_char               *name;
    ngx_log_t            *log;
} ngx_pool_cleanup_file_t;


ngx_pool_t *ngx_create_pool(size_t size, ngx_log_t *log);
void ngx_destroy_pool(ngx_pool_t *pool);
void ngx_reset_pool(ngx_pool_t *pool);

void *ngx_palloc(ngx_pool_t *pool, size_t size);
void *ngx_pnalloc(ngx_pool_t *pool, size_t size);
void *ngx_pcalloc(ngx_pool_t *pool, size_t size);
void *ngx_pmemalign(ngx_pool_t *pool, size_t size, size_t alignment);
ngx_int_t ngx_pfree(ngx_pool_t *pool, void *p);


ngx_pool_cleanup_t *ngx_pool_cleanup_add(ngx_pool_t *p, size_t size);
void ngx_pool_run_cleanup_file(ngx_pool_t *p, ngx_fd_t fd);
void ngx_pool_cleanup_file(void *data);
void ngx_pool_delete_file(void *data);


#endif /* _NGX_PALLOC_H_INCLUDED_ */
