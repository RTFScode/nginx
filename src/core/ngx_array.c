
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>

/*
*	创建nginx数组，初始化一个nginx数组的管理结构
*/
ngx_array_t *
ngx_array_create(ngx_pool_t *p, ngx_uint_t n, size_t size)
{
    ngx_array_t *a;
	//在内存池申请内存给这个数组变量
    a = ngx_palloc(p, sizeof(ngx_array_t));
    if (a == NULL) {
        return NULL;
    }
	//进行初始化
    if (ngx_array_init(a, p, n, size) != NGX_OK) {
        return NULL;
    }

    return a;
}

/*
*	销毁nginx数组
*/
void
ngx_array_destroy(ngx_array_t *a)
{
    ngx_pool_t  *p;

    p = a->pool;
	//首先回收数组元素的内存
    if ((u_char *) a->elts + a->size * a->nalloc == p->d.last) {
        p->d.last -= a->size * a->nalloc;
    }
	//再回收数组管理结构的内存
    if ((u_char *) a + sizeof(ngx_array_t) == p->d.last) {
        p->d.last = (u_char *) a;
    }
}

/*
*	添加一个数组元素
*/
void *
ngx_array_push(ngx_array_t *a)
{
    void        *elt, *new;
    size_t       size;
    ngx_pool_t  *p;
	//判断数组是都已经满
    if (a->nelts == a->nalloc) {

        /* the array is full */

        size = a->size * a->nalloc;

        p = a->pool;
		/*
		*	数组结束位置是d.last         就是pool的可用位置
		*	并且pool剩余内存足够分配一个size的数组元素
		*/
        if ((u_char *) a->elts + size == p->d.last
            && p->d.last + a->size <= p->d.end)
        {
            /*
             * the array allocation is the last in the pool
             * and there is space for new allocation
             */
			//数组扩容一个元素
            p->d.last += a->size;
            a->nalloc++;

        } 
		/*
		*	pool内存不足分配一个元素，则new一个新的数组
		*	大小为:size = a->size * a->nalloc;
		*/	
		else {
            /* allocate a new array */
			/*
			*	分配新内存的时候并没有把原来pool中的数组释放
			*	nginx对pool中内存的释放原则是：
			*	要么释放整个pool，要么不释放
			*/
            new = ngx_palloc(p, 2 * size);
            if (new == NULL) {
                return NULL;
            }
			//将原来的数组元素拷贝过去
            ngx_memcpy(new, a->elts, size);
            a->elts = new;
            a->nalloc *= 2;
        }
    }
	//elt是新数组未使用的第一个元素的地址
    elt = (u_char *) a->elts + a->size * a->nelts;
    a->nelts++;		//未使用的元素下标++,因为只分配一个元素

    return elt;
}

/*
*	多个元素的push，添加多个元素
*/
void *
ngx_array_push_n(ngx_array_t *a, ngx_uint_t n)
{
    void        *elt, *new;
    size_t       size;
    ngx_uint_t   nalloc;
    ngx_pool_t  *p;

	//添加多个元素
    size = n * a->size;

    if (a->nelts + n > a->nalloc) {

        /* the array is full */

        p = a->pool;

        if ((u_char *) a->elts + a->size * a->nalloc == p->d.last
            && p->d.last + size <= p->d.end)
        {
            /*
             * the array allocation is the last in the pool
             * and there is space for new allocation
             */

            p->d.last += size;	//池子可用内存向后偏
            a->nalloc += n;		//元素个数+n

        } else {
            /* allocate a new array */
			/*
			*	分配新数组个数需要在n和a->nalloc之间取较大值
			*	使用三木运算符a > b ? a : b;
			*/
            nalloc = 2 * ((n >= a->nalloc) ? n : a->nalloc);

            new = ngx_palloc(p, nalloc * a->size);
            if (new == NULL) {
                return NULL;
            }

            ngx_memcpy(new, a->elts, a->nelts * a->size);
            a->elts = new;
            a->nalloc = nalloc;
        }
    }

    elt = (u_char *) a->elts + a->size * a->nelts;
    a->nelts += n;		//增加n个元素

    return elt;
}
