/**
 * ngx_hash_t test
 * in this example, it will first save URLs into the memory pool, and IPs saved in static memory.
 * then, give some examples to find IP according to a URL.
 */

#include <stdio.h>
#include "ngx_config.h"
#include "ngx_conf_file.h"
#include "nginx.h"
#include "ngx_core.h"
#include "ngx_string.h"
#include "ngx_palloc.h"
#include "ngx_array.h"
#include "ngx_hash.h"
#include "ngx_log.h"

#define DEEPTH 4
#define Max_Num 13 
#define Max_Size 1024
#define Bucket_Size 64  //256, 64

#define NGX_HASH_ELT_SIZE(name)               \
    (sizeof(void *) + ngx_align((name)->key.len + 2, sizeof(void *)))
	

/* for hash test */
static ngx_str_t urls[Max_Num] = {
    ngx_string("*.com"),  //220.181.111.147
	ngx_string("*.baidu.com.cn"),
	ngx_string("*.baidu.com"),
	ngx_string(".baidu.com"),
	ngx_string("*.google.com"),
    ngx_string("www.sina.com.cn"),  //58.63.236.35
    ngx_string("www.google.com"),  //74.125.71.105
    ngx_string("www.qq.com"),  //60.28.14.190
    ngx_string("www.163.com"),  //123.103.14.237
    ngx_string("www.sohu.com"),  //219.234.82.50
    ngx_string("abo321.org"),  //117.40.196.26
    ngx_string(".abo321.org"),  //117.40.196.26
    ngx_string("www.abo321.*")  //117.40.196.26
};

static ngx_str_t values[Max_Num] = {
    ngx_string("220.181.111.147"),
    ngx_string("220.181.111.147"),
    ngx_string("220.181.111.147"),
    ngx_string("220.181.111.147"),
    ngx_string("220.181.111.147"),
    ngx_string("58.63.236.35"),
    ngx_string("74.125.71.105"),
    ngx_string("60.28.14.190"),
    ngx_string("123.103.14.237"),
    ngx_string("219.234.82.50"),
    ngx_string("117.40.196.26"),
    ngx_string("117.40.196.26"),
    ngx_string("117.40.196.26")
};

#define Max_Url_Len 15
#define Max_Ip_Len 15

#define Max_Num2 3

/* for finding test */
static ngx_str_t urls2[Max_Num2] = {
    ngx_string("*.xx.xx"),  //60.217.58.79
    ngx_string("www.baidu.com"),  //117.79.157.242
    ngx_string("www.baidu.")  //117.79.157.242
};

void* init_hash(ngx_pool_t *pool, ngx_hash_keys_arrays_t *ha, ngx_hash_combined_t *hash);
void dump_pool(ngx_pool_t* pool);
void dump_hash_array(ngx_array_t* a);
void dump_combined_hash(ngx_hash_combined_t *hash, ngx_hash_keys_arrays_t *array);
void dump_hash(ngx_hash_t *hash, ngx_array_t *array);
void* add_urls_to_array(ngx_pool_t *pool, ngx_hash_keys_arrays_t *ha, ngx_array_t *url, ngx_array_t *value);
void find_test(ngx_hash_combined_t *hash, ngx_str_t addr[], int num);
void dump_hash_wildcard(ngx_hash_wildcard_t *wc_hash, ngx_uint_t deepth);

/* for passing compiling */
volatile ngx_cycle_t  *ngx_cycle;
ngx_log_t ngx_log;
void ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err, const char *fmt, ...)
{
}
static int
ngx_http_cmp_dns_wildcards(const void *one, const void *two)
{
    ngx_hash_key_t  *first, *second;

    first = (ngx_hash_key_t *) one;
    second = (ngx_hash_key_t *) two;

    return ngx_dns_strcmp(first->key.data, second->key.data);
}
int main(/* int argc, char **argv */)
{
    ngx_pool_t *pool = NULL;
    ngx_hash_keys_arrays_t array;
    ngx_hash_combined_t hash;
	ngx_int_t loop;
	ngx_array_t *url, *value;
	ngx_str_t *temp;

	hash.wc_head = hash.wc_tail = NULL;

    printf("--------------------------------\n");
    printf("create a new pool:\n");
    printf("--------------------------------\n");


    pool = ngx_create_pool(1024, &ngx_log);

    dump_pool(pool);

    printf("--------------------------------\n");
    printf("create and add urls to it:\n");
    printf("--------------------------------\n");
	if ((url = ngx_array_create(pool, Max_Num, sizeof(ngx_str_t))) == NULL)
	{
		printf("Failed to initialize url!\n");
        return -1;
	}
	if ((value = ngx_array_create(pool, Max_Num, sizeof(ngx_str_t))) == NULL)
	{
		printf("Failed to initialize value!\n");
        return -1;
	}
	//常量字符串是不可修改的，而后面需要修改，所以重新拷贝一份
	for (loop = 0; loop < Max_Num; loop++)
	{
		temp = ngx_array_push(url);
		temp->len = urls[loop].len;
		temp->data = ngx_palloc(pool, urls[loop].len);
		ngx_memcpy(temp->data, urls[loop].data, temp->len);
	}
	//由于key-value中的value的地址必须是4对齐的，所以需要重新拷贝一份vaule
	for (loop = 0; loop < Max_Num; loop++)
	{
		temp = ngx_array_push(value);
		temp->len = values[loop].len;
		temp->data = ngx_palloc(pool, values[loop].len);
		ngx_memcpy(temp->data, values[loop].data, temp->len);
	}
	if (add_urls_to_array(pool, &array, url, value) == NULL)
	{
        printf("Failed to initialize array!\n");
        return -1;
    }
    dump_hash_array(&array.keys);
	dump_hash_array(&array.dns_wc_head);
	dump_hash_array(&array.dns_wc_tail);

    printf("--------------------------------\n");
    printf("the pool:\n");
    printf("--------------------------------\n");
    dump_pool(pool);

    if (init_hash(pool, &array, &hash) == NULL)
    {
        printf("Failed to initialize hash!\n");
        return -1;
    }
    printf("--------------------------------\n");
    printf("the hash:\n");
    printf("--------------------------------\n");
    dump_combined_hash(&hash, &array);
    printf("\n");

    printf("--------------------------------\n");
    printf("the pool:\n");
    printf("--------------------------------\n");
    dump_pool(pool);

    //find test
    printf("--------------------------------\n");
    printf("find test:\n");
    printf("--------------------------------\n");
    find_test(&hash, urls, Max_Num);
    printf("\n");

    find_test(&hash, urls2, Max_Num2);

    //release
    return 0;
}

void* init_hash(ngx_pool_t *pool, ngx_hash_keys_arrays_t *ha, ngx_hash_combined_t *hash)
{
    ngx_hash_init_t hinit;

    ngx_cacheline_size = 32;  //here this variable for nginx must be defined
    hinit.hash = NULL;  //if hinit.hash is NULL, it will alloc memory for it in ngx_hash_init
    hinit.key = &ngx_hash_key_lc;  //hash function
    hinit.max_size = Max_Size;
    hinit.bucket_size = Bucket_Size;
    hinit.name = "my_hash_sample";
    hinit.pool = pool;  //the hash table exists in the memory pool
	hinit.temp_pool = ha->temp_pool;

    if (ha->keys.nelts) {  //无通配
		hinit.hash = &hash->hash;
        if (ngx_hash_init(&hinit, ha->keys.elts, ha->keys.nelts) != NGX_OK) {
            goto failed;
        }
    }
    if (ha->dns_wc_head.nelts) {  //前缀通配
		hinit.hash = NULL;
        ngx_qsort(ha->dns_wc_head.elts, (size_t) ha->dns_wc_head.nelts,
                  sizeof(ngx_hash_key_t), ngx_http_cmp_dns_wildcards);
		dump_hash_array(&ha->dns_wc_head);
			
        if (ngx_hash_wildcard_init(&hinit, ha->dns_wc_head.elts,
                                   ha->dns_wc_head.nelts)
            != NGX_OK)
        {
            goto failed;
        }
        hash->wc_head = (ngx_hash_wildcard_t *) hinit.hash;
    }

    if (ha->dns_wc_tail.nelts) {  //后缀通配
        ngx_qsort(ha->dns_wc_tail.elts, (size_t) ha->dns_wc_tail.nelts,
                  sizeof(ngx_hash_key_t), ngx_http_cmp_dns_wildcards);
		dump_hash_array(&ha->dns_wc_tail);
		hinit.hash = NULL;
        if (ngx_hash_wildcard_init(&hinit, ha->dns_wc_tail.elts,
                                   ha->dns_wc_tail.nelts)
            != NGX_OK)
        {
            goto failed;
        }

        hash->wc_tail = (ngx_hash_wildcard_t *) hinit.hash;
    }

    //ngx_destroy_pool(ha->temp_pool);
	return hash;
failed:
    //ngx_destroy_pool(ha->temp_pool);
    return NULL;
}

void dump_pool(ngx_pool_t* pool)
{
    while (pool)
    {
        printf("pool = %p\n", pool);
        printf("  .d\n");
        printf("    .last = %p\n", pool->d.last);
        printf("    .end = %p\n", pool->d.end);
        printf("    .next = %p\n", pool->d.next);
        printf("    .failed = %d\n", pool->d.failed);
        printf("  .max = %d\n", pool->max);
        printf("  .current = %p\n", pool->current);
        printf("  .chain = %p\n", pool->chain);
        printf("  .large = %p\n", pool->large);
        printf("  .cleanup = %p\n", pool->cleanup);
        printf("  .log = %p\n", pool->log);
        printf("available pool memory = %d\n\n", pool->d.end - pool->d.last);
        pool = pool->d.next;
    }
}

void dump_hash_array(ngx_array_t* a)
{
    char prefix[] = "              ";
	ngx_uint_t i;

    if (a == NULL)
        return;

    printf("array = %p\n", a);
    printf("  .elts = %p\n", a->elts);
    printf("  .nelts = %d\n", a->nelts);
    printf("  .size = %d\n", a->size);
    printf("  .nalloc = %d\n", a->nalloc);
    printf("  .pool = %p\n", a->pool);

    printf("  elements:\n");
    ngx_hash_key_t *ptr = a->elts;
    for (i = 0; i < a->nelts; i++)
    {
        printf("    %p: {key = (\"%.*s\"%.*s, %-2d), key_hash = %-11d, value = \"%.*s\"%.*s}\n", 
            ptr + i, ptr[i].key.len, ptr[i].key.data, Max_Url_Len - ptr[i].key.len, prefix, ptr[i].key.len, 
            ptr[i].key_hash, ((ngx_str_t*)ptr[i].value)->len, ((ngx_str_t*)ptr[i].value)->data, Max_Ip_Len - ((ngx_str_t*)ptr[i].value)->len, prefix);
    }
    printf("\n");
}

/**
 * pass array pointer to read elts[i].key_hash, then for getting the position - key
 */
void dump_combined_hash(ngx_hash_combined_t *hash, ngx_hash_keys_arrays_t *array)
{
	dump_hash(&hash->hash, &array->keys);
	dump_hash_wildcard(hash->wc_head, 0);
	dump_hash_wildcard(hash->wc_tail, 0);
}
void dump_hash_wildcard(ngx_hash_wildcard_t *wc_hash, ngx_uint_t deepth)
{
	ngx_uint_t loop;
    char prefix[] = "                         ";
	ngx_hash_wildcard_t *wdc;
	ngx_hash_t *hash = &wc_hash->hash;

	if (wc_hash == NULL)
		return;
	if (wc_hash->value != NULL)
		printf("%.*svalue = \"%.*s\"\n", deepth * DEEPTH, prefix, ((ngx_str_t*)wc_hash->value)->len,
				((ngx_str_t*)wc_hash->value)->data);
	else
		printf("%.*svalue = NULL\n", deepth * DEEPTH, prefix);
    printf("%.*shash = %p: **buckets = %p, size = %d\n", deepth * DEEPTH, prefix, hash, hash->buckets, hash->size);

    for (loop = 0; loop < hash->size; loop++)
    {
        ngx_hash_elt_t *elt = hash->buckets[loop];
        printf("%.*s%p: buckets[%d] = %p\n", deepth * DEEPTH * 2, prefix, &(hash->buckets[loop]), loop, elt);
		if (elt)
		{
			while (elt->value)
			{
				uintptr_t value = (uintptr_t)elt->value;
				if ((value & 3) == 0 || (value & 3) == 1)  //注意位操作与逻辑运算符的优先级
				{
					value &= (uintptr_t)~3;
					//值得参考的是%.*s的输出，通过参数控制输出字符的个数
					printf("%.*sbuckets %d: %p {value = \"%.*s\"%.*s, len = %d, name = \"%.*s\"%.*s}\n", 
						deepth * DEEPTH * 2, prefix, loop, elt, ((ngx_str_t*)value)->len, ((ngx_str_t*)value)->data, Max_Ip_Len - ((ngx_str_t*)value)->len, prefix, 
						elt->len, elt->len, elt->name, Max_Url_Len - elt->len, prefix); 
				}
				else
				{
					wdc = (ngx_hash_wildcard_t *)(value & (uintptr_t)~3);
					printf("%.*sbuckets %d: %p: {value = \"%-16p\", len = %d, name = \"%.*s\"%.*s}\n", 
						deepth * DEEPTH * 2, prefix, loop, elt, wdc, elt->len, elt->len, elt->name, Max_Url_Len - elt->len, prefix); 
					dump_hash_wildcard(wdc, deepth + 1);
				}
				elt = (ngx_hash_elt_t *)ngx_align_ptr(&elt->name[0] + elt->len, sizeof(void *));
			}
		}
    }
}
void dump_hash(ngx_hash_t *hash, ngx_array_t *array)
{
    ngx_uint_t loop;
    char prefix[] = "                 ";
    u_short test[Max_Num] = {0};
    ngx_uint_t key;
    ngx_hash_key_t* elts;

    if (hash == NULL)
        return;

    printf("hash = %p: **buckets = %p, size = %d\n", hash, hash->buckets, hash->size);

    for (loop = 0; loop < hash->size; loop++)
    {
        ngx_hash_elt_t *elt = hash->buckets[loop];
        printf("  %p: buckets[%d] = %p\n", &(hash->buckets[loop]), loop, elt);
    }
    printf("\n");

    elts = (ngx_hash_key_t*)array->elts;
    for (loop = 0; loop < array->nelts; loop++)
    {
        key = elts[loop].key_hash % hash->size;
        ngx_hash_elt_t *elt = (ngx_hash_elt_t *) ((u_char *) hash->buckets[key] + test[key]);

		//值得参考的是%.*s的输出，通过参数控制输出字符的个数
        printf("  key %-10d: buckets %d: %p: {value = \"%.*s\"%.*s, len = %d, name = \"%.*s\"%.*s}\n", 
            elts[loop].key_hash, key, elt, ((ngx_str_t*)elt->value)->len, ((ngx_str_t*)elt->value)->data, Max_Ip_Len - ((ngx_str_t*)elt->value)->len, prefix, elt->len,  
            elt->len, elt->name, Max_Url_Len - elt->len, prefix); //replace elt->name with url

        test[key] = (u_short) (test[key] + NGX_HASH_ELT_SIZE(&elts[loop]));
    }
}


void* add_urls_to_array(ngx_pool_t *pool, ngx_hash_keys_arrays_t *ha, ngx_array_t *url, ngx_array_t *value)
{
	ngx_uint_t loop;
	ngx_int_t	rc;
	ngx_str_t	*strUrl, *strValue;
	
	memset(ha, 0, sizeof(ngx_hash_keys_arrays_t));
	ha->temp_pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, &ngx_log);
	ha->pool = pool;
    if (ngx_hash_keys_array_init(ha, NGX_HASH_LARGE) != NGX_OK) {
        goto failed;
    }
	
	strUrl = url->elts;
	strValue = value->elts;
	for (loop = 0; loop < url->nelts; loop++)
	{
		rc = ngx_hash_add_key(ha, &strUrl[loop], &strValue[loop],
                                  NGX_HASH_WILDCARD_KEY);

            if (rc == NGX_ERROR) {
                goto failed;
            }
	}
    return ha;    

failed:
    ngx_destroy_pool(ha->temp_pool);
    return NULL;
}

void find_test(ngx_hash_combined_t *hash, ngx_str_t addr[], int num)
{
    ngx_uint_t key;
    int loop;
    char prefix[] = "          ";

    for (loop = 0; loop < num; loop++)
    {
        key = ngx_hash_key_lc(addr[loop].data, addr[loop].len);
        ngx_str_t *value = ngx_hash_find_combined(hash, key, addr[loop].data, addr[loop].len);
        if (value)
        {
            printf("(url = \"%s\"%.*s, key = %-11d) found, (ip = \"%.*s%.*s\")\n", 
                addr[loop].data, Max_Url_Len - addr[loop].len, prefix, key, value->len, value->data, Max_Ip_Len - value->len, prefix);
        }
        else
        {
            printf("(url = \"%s\"%.*s, key = %-11d) not found!\n", 
                addr[loop].data, Max_Url_Len - addr[loop].len, prefix, key);
        }
    }
}

