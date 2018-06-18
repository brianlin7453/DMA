/**
 * All functions you make for the assignment must be implemented in this file.
 * Do not submit your assignment with a main function in this file.
 * If you submit with a main function in this file, you will get a zero.
 */
#include <string.h>
#include <errno.h>
#include "sfmm.h"
#include <stdio.h>
#include <stdlib.h>
void make_sf_footer(size_t size,void *address,int allocated,size_t requested_size,int padded);
void split_page(char *address,size_t size);
void put_in_list(sf_free_header *header, free_list *list);
void put_in_free_list(sf_free_header *header);
void place_sf_header(size_t size, void* address, int allocated,int padded);
void remove_node(sf_free_header *delete,free_list *list);
void add_page_to_free_list(void *new_page_ptr,size_t block_size);
void calculate_smallest_block_size();
void free_header(sf_header *ptr);
void coalesce_foward(sf_header *ptr,size_t next_block_size);

void* allocate_mult_page(size_t size);
void* get_free_block(size_t size);
void* new_list_allocate(size_t size, void *page_ptr);
void *upgrade(void* ptr, size_t new_payload_size);
void *downgrade(void* ptr, size_t new_payload_size);

sf_free_header *make_sf_free_header(void *address,sf_header header,sf_free_header *next,sf_free_header *prev);
sf_free_header *search_specific_list(free_list *free_list_ptr, size_t size);
sf_free_header *search_list(size_t size);
sf_free_header *make_mult_page(size_t requested_size, size_t block_size);

sf_header *split_allocate_block(sf_free_header *ptr, size_t size);
sf_header *coalesce_new_page(void *new_page_ptr);
sf_header *get_header_from_footer(sf_footer *footer);
sf_header *make_sf_header(size_t size,void *address,int allocated,int padded);


int get_which_list(size_t size);
int calculate_block_size(size_t size);
int pad_calc(size_t size);
int validate_free_ptr(void *ptr);
/**
 * You should store the heads of your free lists in these variables.
 * Doing so will make it accessible via the extern statement in sfmm.h
 * which will allow you to pass the address to sf_snapshot in a different file.
 */
void *current_heap_ptr;
free_list seg_free_list[4] = {
    {NULL, LIST_1_MIN, LIST_1_MAX},
    {NULL, LIST_2_MIN, LIST_2_MAX},
    {NULL, LIST_3_MIN, LIST_3_MAX},
    {NULL, LIST_4_MIN, LIST_4_MAX}
};
size_t smallest_list_size = 0;
int sbrk_counter = 0;
int sf_errno = 0;
void* sf_malloc(size_t size){
    calculate_smallest_block_size();
    char *address;
	if (size <= 0 || size > 4*PAGE_SZ){
        //sf_errno = ENOMEM;
        sf_errno = EINVAL;
        return NULL;
    }
    if (size > PAGE_SZ)
        address = allocate_mult_page(size);
    else
        address = get_free_block(size);
    if (address == NULL){
        sf_errno = ENOMEM;
        return NULL;
    }
    return address + 8;
}

void *sf_realloc(void *ptr, size_t size) {
    int valid = validate_free_ptr(ptr);
    if (valid == -1)
        abort();
    if(size == 0){
        sf_free(ptr);
        return NULL;
    }
    if (size < 0 || size > 4*PAGE_SZ){
        sf_errno = EINVAL;
        return NULL;
    }
    ptr = ptr - 8;
    sf_header *header_ptr = (sf_header*)ptr;
    size_t header_block_size = header_ptr->block_size << 4;
    if (size > header_block_size)
        return upgrade(ptr,size);
    else if (size < header_block_size)
        return downgrade(ptr,size);
    return ptr + 8;
}

void *upgrade(void* ptr, size_t new_payload_size){
    sf_header *header_ptr = (sf_header*)ptr;
    size_t old_block_size = header_ptr->block_size << 4;
    void* new_block_ptr = sf_malloc(new_payload_size);
    if(new_block_ptr == NULL)
        return NULL;
    memcpy(new_block_ptr,ptr + 8,old_block_size);
    sf_free(ptr+8);
    return (void*)new_block_ptr;
}

void *downgrade(void* ptr, size_t new_payload_size){
    sf_header *header_ptr = (sf_header*)ptr;
    size_t old_block_size = header_ptr->block_size << 4;
    size_t new_allocated_block_size = calculate_block_size(new_payload_size);
    int padded = new_payload_size % 16 != 0;
    int free_block_size = old_block_size - new_allocated_block_size;
    if (free_block_size < smallest_list_size){
        free_block_size = 0;
    }
    if(free_block_size != 0){
        sf_header *top_sf_header = make_sf_header(new_allocated_block_size,header_ptr,1,padded);
        make_sf_footer(new_allocated_block_size,(char*)header_ptr + new_allocated_block_size - 8,1,new_payload_size,padded);
        sf_header *new_sf_header = make_sf_header(free_block_size,(char*)header_ptr + new_allocated_block_size,1,0);
        //sf_free_header *free_ptr = make_sf_free_header(new_sf_header,*new_sf_header,NULL,NULL);
        //put_in_free_list(free_ptr);
        sf_footer *old_footer_ptr = ((void*)header_ptr + old_block_size - 8);
        old_footer_ptr->allocated = 1;
        old_footer_ptr->padded = 0;
        old_footer_ptr->two_zeroes = 0;
        old_footer_ptr->block_size = free_block_size >> 4;
        old_footer_ptr->requested_size = free_block_size -16;
        sf_free((void*)new_sf_header + 8);
        return (void*)top_sf_header + 8;
    }
    else{
        sf_header *top_sf_header = make_sf_header(old_block_size,header_ptr,1,padded);
        sf_footer *old_footer_ptr = ((void*)ptr + old_block_size - 8);
        old_footer_ptr->block_size = free_block_size >> 4;
        old_footer_ptr->requested_size = new_payload_size;
        return (void*)top_sf_header + 8;
    }
    return NULL;
}

void sf_free(void *ptr){
    int valid = validate_free_ptr(ptr);
    if (valid == -1)
        abort();
    ptr = ptr -8;
    sf_header *header_ptr = ptr;
    size_t block_size = header_ptr->block_size << 4;
    sf_header *next_header_ptr = ptr + block_size;
    size_t next_block_size = next_header_ptr->block_size << 4;
    int allocated = next_header_ptr->allocated;
    if (next_block_size > 0 && allocated == 0){
        sf_free_header *fhp = (sf_free_header*)next_header_ptr;
        int list_index = get_which_list(next_block_size);
        free_list *seg_ptr = &seg_free_list[list_index];
        remove_node(fhp,seg_ptr);
        if ((void*)next_header_ptr < get_heap_end())
            coalesce_foward(header_ptr,next_block_size);
        sf_free_header *free_ptr = make_sf_free_header(header_ptr,*header_ptr,NULL,NULL);
        put_in_free_list(free_ptr);
    }
    else{
        free_header(header_ptr);
        sf_free_header *free_ptr = make_sf_free_header(header_ptr,*header_ptr,NULL,NULL);
        put_in_free_list(free_ptr);
    }
}

int validate_free_ptr(void *ptr){
    if (ptr == NULL)
        return -1;
    void *heap_begin = get_heap_start();
    void *heap_end = get_heap_end();
    ptr = ptr - 8;
    if (ptr < heap_begin)
        return -1;
    sf_header *header_ptr = (sf_header*)ptr;
    size_t header_block_size = header_ptr->block_size << 4;
    void *footer_ptr_calc = ptr + header_block_size - 8;
    if ((footer_ptr_calc + 8) > heap_end)
        return -1;

    sf_footer *footer_ptr = (sf_footer*)footer_ptr_calc;
    int head_pad = header_ptr->padded;
    int foot_pad = footer_ptr->padded;
    if (head_pad != foot_pad){
        return -1;
    }
    else if(header_ptr->allocated == 0){
        return -1;
    }
    else if (footer_ptr->allocated == 0){
        return -1;
    }

    return 1;
}

void coalesce_foward(sf_header *ptr,size_t next_block_size){
    size_t block_one_size = ptr->block_size << 4;
    size_t total_block_size = block_one_size + next_block_size;
    ptr->allocated = 0;
    ptr->padded = 0;
    ptr->block_size = total_block_size >> 4;
    sf_footer *next_footer_ptr = (void*)ptr + total_block_size - 8;
    next_footer_ptr->allocated = 0;
    next_footer_ptr->padded = 0;
    next_footer_ptr->block_size = total_block_size >> 4;
    next_footer_ptr->requested_size = 0;
}

void free_header(sf_header *ptr){
    sf_header *header_ptr = ptr;
    size_t block_size = header_ptr->block_size << 4;
    header_ptr->allocated = 0;
    header_ptr->padded = 0;
    sf_footer *footer_ptr = (void*)header_ptr + block_size - 8;
    footer_ptr->allocated = 0;
    footer_ptr->padded = 0;
    footer_ptr->requested_size = 0;
}

void* allocate_mult_page(size_t size){
    int block_size = calculate_block_size(size);
    sf_free_header *list_search = search_list(block_size);
    if (list_search == NULL){
        list_search = make_mult_page(size,block_size);
        if (list_search == NULL)
            return NULL;
    }
    sf_header *header_ptr = split_allocate_block(list_search, size);
    return header_ptr;
}

sf_free_header *make_mult_page(size_t requested_size, size_t block_size){
    int ps = PAGE_SZ;
    int num_pages = (block_size / ps) + 1;
    void *start_ptr;
    for (int i = 0; i < num_pages ; i++){
        sbrk_counter++;
        if (sbrk_counter != 5){
            if (i == 0)
                start_ptr = sf_sbrk();
            else
                sf_sbrk();
        }
        else{
            sf_errno = ENOMEM;
            return NULL;
        }
    }
    int insert_size = (ps*num_pages);
    sf_header *header_ptr = make_sf_header(insert_size,start_ptr,0,0);
    void *footer_address = (void*)start_ptr + (PAGE_SZ*num_pages) - 8;
    make_sf_footer(insert_size,footer_address,0,0,0);
    sf_free_header *free_ptr = make_sf_free_header(header_ptr,*header_ptr,NULL,NULL);
    put_in_free_list(free_ptr);
    return free_ptr;
}

void* get_free_block(size_t size){
    int block_size = calculate_block_size(size);
    sf_free_header *list_search = search_list(block_size);
    if (list_search == NULL){
        sbrk_counter++;
        if (sbrk_counter != 5){
            sf_header *new_page_ptr = sf_sbrk();
            new_page_ptr = coalesce_new_page(new_page_ptr);
            list_search = search_list(block_size);
        }
        else{
            sf_errno = ENOMEM;
            return NULL;
        }
    }
    sf_header *header_ptr = split_allocate_block(list_search, size);
    return header_ptr;
}

sf_header *coalesce_new_page(void *new_page_ptr){
    sf_header *header_from_footer;
    sf_footer *prev_block_footer = new_page_ptr - 8;
    if (prev_block_footer->block_size == 0){
        add_page_to_free_list(new_page_ptr,PAGE_SZ);
        return new_page_ptr;
    }
    else{
        header_from_footer = get_header_from_footer(prev_block_footer);
        sf_free_header *fhp = (sf_free_header*)header_from_footer;
        int list_index = get_which_list(header_from_footer->block_size << 4);
        free_list *seg_ptr = &seg_free_list[list_index];
        remove_node(fhp,seg_ptr);
        size_t header_block_size = header_from_footer->block_size << 4;
        header_block_size = header_block_size + PAGE_SZ;
        header_from_footer->block_size = header_block_size >> 4;
        void *footer_address = (void*)header_from_footer + header_block_size - 8;
        make_sf_footer(header_block_size,footer_address,0,0,0);
        put_in_free_list(fhp);
    }
    return header_from_footer;
}

sf_header *get_header_from_footer(sf_footer *prev_block_ptr){
    int block_size = prev_block_ptr->block_size << 4;
    sf_header *header_ptr = (sf_header*)((char*)prev_block_ptr + 8 - block_size);
    return header_ptr;
}

void add_page_to_free_list(void *new_page_ptr, size_t block_size){
    sf_header *header = make_sf_header(block_size,new_page_ptr,0,0);
    char *end = (char*)header + block_size - 8;
    make_sf_footer(block_size,end,0,0,0);
    sf_free_header *free_header_ptr = make_sf_free_header(header,*header,NULL,NULL);
    put_in_free_list(free_header_ptr);
}

sf_header *split_allocate_block(sf_free_header *ptr, size_t size){
    int new_allocated_block_size = calculate_block_size(size);
    int padded = size % 16 != 0;
    sf_header header = ptr->header;
    int header_block_size = header.block_size << 4;
    //free_list cur_list = get_which_list(size);
    int list_index = get_which_list(header_block_size);
    free_list *seg_ptr = &seg_free_list[list_index];
    remove_node(ptr,seg_ptr);
    int free_block_size = header_block_size - new_allocated_block_size;
    if (free_block_size < smallest_list_size){
        header_block_size = header_block_size + free_block_size;
        free_block_size = 0;
    }
    if (free_block_size != 0){
        sf_header *top_sf_header = make_sf_header(new_allocated_block_size,ptr,1,padded);
        make_sf_footer(calculate_block_size(size),(char*)ptr + new_allocated_block_size - 8,1,size,padded);
        sf_header *free_sf_header = make_sf_header(free_block_size,(char*)ptr + new_allocated_block_size,0,0);
        sf_footer *old_footer_ptr = ((void*)ptr + header_block_size - 8);
        old_footer_ptr->block_size = free_block_size >> 4;
        old_footer_ptr->requested_size = 0;
        sf_free_header *list_header = make_sf_free_header((char*)ptr + new_allocated_block_size,*free_sf_header,NULL,NULL);
        put_in_free_list(list_header);
        return top_sf_header;
    }
    else{
        sf_header *top_sf_header = make_sf_header(new_allocated_block_size,ptr,1,padded);
        sf_footer *old_footer_ptr = ((void*)ptr + header_block_size - 8);
        old_footer_ptr->requested_size = size;
        old_footer_ptr->allocated = 1;
        return top_sf_header;
    }
    //sf_free_header *new_free_header = make_sf_free_header()x
    sf_header *header_ptr = &header;
    return header_ptr;
}

sf_free_header* search_list(size_t size){
    for (int i = 0; i < sizeof(seg_free_list)/sizeof(seg_free_list[0]);i++){
        free_list list = seg_free_list[i];
        free_list *free_list_ptr = &seg_free_list[i];
        if (size < list.max){
            if (list.head != NULL){
                void* free_block_address = search_specific_list(free_list_ptr,size);
                if (free_block_address != NULL)
                    return free_block_address;
            }
        }
    }
    return NULL;
}

sf_free_header* search_specific_list(free_list *free_list_ptr, size_t size){
    sf_free_header *free_header_ptr = free_list_ptr->head;
    sf_header header = free_header_ptr->header;
    int block_size = header.block_size << 4;
    if (block_size >= size){
        //remove_node(free_header_ptr);
        return free_header_ptr;
    }
    return NULL;
}

void put_in_free_list(sf_free_header *header){

    sf_header normal_header = header->header;
    int block_size = normal_header.block_size << 4;
    for (int i = 0; i < sizeof(seg_free_list)/sizeof(seg_free_list[0]);i++){
        free_list list = seg_free_list[i];
        free_list *free_list_ptr = &seg_free_list[i];
        if (list.min <= block_size && list.max >= block_size){
            put_in_list(header,free_list_ptr);
        }
    }
}

void put_in_list(sf_free_header *header,free_list *list){
    if(list->head != NULL){
        sf_free_header *head_list = list->head;
        head_list->prev = header;
        list->head = header;
        header->next = head_list;
    }
    else{
        list->head = header;
    }

}

void remove_node(sf_free_header *delete,free_list *list){
    sf_free_header *next;
    sf_free_header *prev;
    if(list->head == NULL && delete == NULL)
        return;
    if (list->head == delete && delete->next == NULL){
        list->head = NULL;
        delete->next = NULL;
        delete->prev = NULL;
        return;
    }
    if (list->head == delete && delete->next != NULL){
        next = delete->next;
        list-> head = next;
        delete->next = NULL;
        delete->prev = NULL;
        next->prev = NULL;
    }
    if(list->head != delete && delete->next == NULL){
            prev = delete->prev;
            prev->next = NULL;
            delete->prev = NULL;
            return;
    }
    else{
        prev = delete->prev;
        next = delete->next;
        prev->next = next;
        next->prev = prev;
        return;
    }
}

sf_header *make_sf_header(size_t size, void* address, int allocated,int padded){
    sf_header *header = address;
    header->allocated = allocated;
    header->padded = padded;
    header->block_size = size >> 4;
    return header;
}

sf_free_header *make_sf_free_header(void *address,sf_header header,sf_free_header *next,sf_free_header *prev){
    sf_free_header *free_header = address;
    free_header->next = next;
    free_header->prev = prev;
    free_header->header = header;
    return free_header;
}

void make_sf_footer(size_t size, void* address, int allocated, size_t requested_size,int padded){
    sf_footer *footer = address;
    footer->allocated = allocated;
    footer->padded = padded;
    footer->block_size = size >> 4;
    footer->requested_size = requested_size;
}

void place_sf_header(size_t size, void* address, int allocated,int padded){
    sf_header *header = address;
    header->allocated = allocated;
    header->padded = padded;
    header->block_size = size >> 4;
}

int pad_calc(size_t size){
    int mod = size % 16;
    return 16-mod;
}

int calculate_block_size(size_t size){
    int padding = 0;
    if (size % 16 != 0){
        padding = pad_calc(size);
    }
    return 8 + 8 + size + padding;
}

int get_which_list(size_t size){
    for (int i = 0; i < FREE_LIST_COUNT ; i++){
        free_list list = seg_free_list[i];
        if (list.min <= size && list.max >= size)
            return i;
    }
    return -1;
}

void calculate_smallest_block_size(){
    int smallest = LIST_1_MIN;
    for (int i = 1; i < FREE_LIST_COUNT ; i++){
        if (seg_free_list[i].min < smallest)
            smallest = seg_free_list[i].min;
    }
    smallest_list_size = smallest;
}


