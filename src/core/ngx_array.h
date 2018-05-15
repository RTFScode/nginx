
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_ARRAY_H_INCLUDED_
#define _NGX_ARRAY_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


/*
*	nginx数组的使用是依赖ngx内存池的
*	并且nginx数组是设计用来存储小数据的
*/
typedef struct {
    void        *elts;		//数组的内存地址，首元素指针
    ngx_uint_t   nelts;		//未使用元素的索引
    size_t       size;		//每个元素的大小
    ngx_uint_t   nalloc;	//分配元素个数
    ngx_pool_t  *pool;		//内存池，就是整个内存池的首节点
} ngx_array_t;

/*
*	创建nginx数组
*	初始化了一个nginx数组的管理结构ngx_array_t*类型
*/
ngx_array_t *ngx_array_create(ngx_pool_t *p, ngx_uint_t n, size_t size);
/*
*	销毁一个nginx数组
*	销毁任务包括：	1.nginx数组内存
*				   2.nginx数组管理结构的内存
*/
void ngx_array_destroy(ngx_array_t *a);
/*
*	添加一个新数组元素的内存
*/
void *ngx_array_push(ngx_array_t *a);
/*
*	添加n个新数组元素的内存
*/
void *ngx_array_push_n(ngx_array_t *a, ngx_uint_t n);


/*
*	nginx数组的初始化
*/
static ngx_inline ngx_int_t
ngx_array_init(ngx_array_t *array, ngx_pool_t *pool, ngx_uint_t n, size_t size)
{
    /*
     * set "array->nelts" before "array->elts", otherwise MSVC thinks
     * that "array->nelts" may be used without having been initialized
     */

    array->nelts = 0;
    array->size = size;
    array->nalloc = n;		//元素个数
    array->pool = pool;
	
	//elts指向数组的内存地址
    array->elts = ngx_palloc(pool, n * size);
    if (array->elts == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


#endif /* _NGX_ARRAY_H_INCLUDED_ */
