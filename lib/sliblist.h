/*
 * A simple linked list implementation.
 *
 * Copyright (C) 2013 VoIP Embedded, Inc.
 *
 * sliblist is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version
 *
 * sliblist is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA
 *
 * 2013-02-25 initial implementation (osas)
 */


#ifndef S_LIB_LIST_H
#define S_LIB_LIST_H

#include <sys/types.h>
#include <stddef.h>


/**
 * Structure defining the simple linked list.
 */
typedef struct slinkedl_list slinkedl_list_t;

/**
 * Structure defining an elemnt of a simple linked list.
 */
typedef struct slinkedl_element slinkedl_element_t;


/**
 * Memory allocator to be used in list operations.
 *
 * @param size Size of the memory block to be allocated.
 * @return A pointer to the requsted memory block.
 *         NULL on error;
 *         non NULL on success.
 */
void *(slinkedl_alloc) (size_t size);
typedef void *(slinkedl_alloc_f) (size_t size);

/**
 * Memory de-allocator to be used in list operations.
 *
 * @param ptr Ponter to the emmory block to be freeed.
 */
void (slinkedl_dealloc) (void *ptr);
typedef void (slinkedl_dealloc_f) (void *ptr);


/**
 * Function to be called by slinkedl_traverse while traversing the list.
 *
 * @param e_data pointer to data stored by the current element.
 * @param data pointer to given data to work with.
 * @param r_data pointer to data returned by this function.
 * return <0 on error and exit list traversal;
 * return  0 on no action on current list elemnt and
 *           continue list traversal;
 * return >0 on action successfully completed on current list element
 *           and exit list traversal.
 * @see slinkedl_traverse()
 */
int (slinkedl_run_data) (void *e_data, void *data, void *r_data);
typedef int (slinkedl_run_data_f) (void *e_data, void *data, void *r_data);


/**
 * List initializer.
 * This function MUST be called in order to initialize a list.
 * It's role is to allocate memory for the list structure and
 * initialize it's internal structure.
 *
 * @param alloc pointer to the memory allocator function.
 * @param dealloc pointer to the memory deallocator function.
 * @return The pointer to the list structure.
 *         - NULL on error (alloc and dealloc must be non NULL);
 *         - non NULL on success.
 */
slinkedl_list_t* slinkedl_init(slinkedl_alloc_f *alloc,
								slinkedl_dealloc_f *dealloc);

/**
 * Insert a list elemnt at the beginning of the list.
 * One block of memory will be allocated for the whole element.
 * The memory will be allocated using the memory allocator
 * provided to the list during initialization.
 *
 * @param list The list to operate on.
 * @param e_size size of the element data to be store by the new element.
 * @return A pointer to a block of memory with size e_size.
 *         - NULL on error;
 *         - non NULL on success.
 *         The application will use the returned pointer to populate
 *         the memory block with it's data.
 * @see slinkedl_init()
 */
void *slinkedl_prepend(slinkedl_list_t *list, size_t e_size);

/**
 * Insert a list elemnt at the end of the list.
 * One block of memory will be allocated for the whole element.
 * The memory will be allocated using the memory allocator
 * provided to the list during initialization.
 *
 * @param list The list to operate on.
 * @param e_size size of the element data to be store by the new element.
 * @return A pointer to a block of memory with size e_size.
 *         - NULL on error;
 *         - non NULL on success.
 *         The application will use the returned pointer to populate
 *         the memory block with it's data.
 * @see slinkedl_init()
 */
void *slinkedl_append(slinkedl_list_t *list, size_t e_size);

/**
 * Traverse the list and execute run_data for each element,
 * until run_data returns a non zero value or the extent of the list
 * is reached.
 *
 * @psram lit The list to traverse.
 * @param run_data The funtion to operate on each list element.
 * @param data The data to be used by run_data function.
 * @parama r_data The data returned by run_data function.
 * @return The return code from last run_data call.
 * @see slinkedl_run_data()
 */
int slinkedl_traverse(slinkedl_list_t *list,
		slinkedl_run_data_f run_data, void *data, void *r_data);

/**
 * Retrieve the first element in the list.
 *
 * @param list The list to retrieve the first element from.
 */
void *slinkedl_peek(slinkedl_list_t *list);

/**
 * Destroy the list.
 * Any element in the list will be silently destroyed.
 * If you want to perform some actions on list elemnts before destroying it,
 * use slinkedl_traverse().
 *
 * @param list The list to be distroyed.
 */
void slinkedl_list_destroy(slinkedl_list_t *list);

#endif

