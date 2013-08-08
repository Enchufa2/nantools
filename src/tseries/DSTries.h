/*
 * DSTries.h
 *
 *  This file is part of NaNTools
 *  See http://github.com/Enchufa2/nantools for more information
 *  Copyright 2013 Iñaki Úcar <i.ucar86@gmail.com>
 *  This program is published under a GPLv3 license
 */

#ifndef DSTRIES_H_
#define DSTRIES_H_

typedef struct {
    int id;
    unsigned int srcIP;
    unsigned int srcMask;
    unsigned int dstIP;
    unsigned int dstMask;
} filter_t;

typedef struct filterList filterList_t;

struct filterList{
    filter_t        *filter;
    filterList_t    *next;
    filterList_t    *prev;
};

typedef struct srcNode srcNode_t;
typedef struct dstNode dstNode_t;
typedef void (*DSTries_callback)(void *, int);
typedef int (*DSTries_IP_extract)(void *header, const u_char *bytes, unsigned int *srcIP, unsigned int *dstIP);

// Dada una línea de texto con subredes de origen y destino (srcIP srcMask dstIP dstMask), procesa el filtro y lo añade a la lista. Devuelve 0 en caso de éxito, -1 en caso contrario.
int DSTries_add_filter(filterList_t **filterList, char *filterString, int id);

// Nuevo árbol
dstNode_t *DSTries_new_tree();

// Inserta una lista de filtros dada. Devuelve 1 en caso de éxito, 0 en caso contrario.
int DSTries_insert_filterList(dstNode_t *root, filterList_t **filterList);

// Función para filtrar por un par de IPs. Para todos aquellos filtros que se verifican, se ejecuta la función de callback. Devuelve el número de filtros que se verifican.
int DSTries_filter(dstNode_t *root, void *header, const u_char *bytes, DSTries_IP_extract extractor, DSTries_callback callback, void *args);

// Destructor. Libera toda la estructura, pero no los filtros.
void DSTries_destroy_tree(dstNode_t *root);

// Destructor. Libera toda la estructura junto con los filtros.
void DSTries_destroy_filterList(filterList_t *filterList);

#endif /* DSTRIES_H_ */
