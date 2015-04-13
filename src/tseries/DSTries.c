/*
 * DSTries.c
 *
 *  This file is part of NaNTools
 *  See http://github.com/Enchufa2/nantools for more information
 *  Copyright 2013 Iñaki Úcar <i.ucar86@gmail.com>
 *  This program is published under a GPLv3 license
 */

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "DSTries.h"

#define TREEORDER 2     // Árbol binario
#define TREEDEPTH 32    // Direcciones de 32 bits

// Devuelve el bit x de y teniendo en cuenta que y lleva orden de red
#define BIT(x, y) ((y >> (x / 8) * 8 + 7 - (x % 8)) & 0x0001)

static unsigned int dstID;

struct srcNode {
    unsigned int    dstID;
    srcNode_t       *child[TREEORDER];
    filter_t        *filter;
    srcNode_t       *ancestor;
};

struct dstNode {
    unsigned int    id;
    dstNode_t       *child[TREEORDER];
    srcNode_t       *srcRoot;
};

// Dada una línea de texto con subredes de origen y destino (srcIP srcMask dstIP dstMask), procesa el filtro y lo añade a la lista. Devuelve 0 en caso de éxito, -1 en caso contrario.
int DSTries_add_filter(filterList_t **filterList, char *filterString, int id) {
    if (!filterString) return -1;

    // Extraigo las IPs del string
    unsigned int srcIP, srcMask, dstIP, dstMask;
    char srcIPstr[INET_ADDRSTRLEN], srcMaskstr[INET_ADDRSTRLEN], dstIPstr[INET_ADDRSTRLEN], dstMaskstr[INET_ADDRSTRLEN];
    sscanf(filterString, "%s %s %s %s", srcIPstr, srcMaskstr, dstIPstr, dstMaskstr);
    inet_pton(AF_INET, srcIPstr, &srcIP);
    inet_pton(AF_INET, srcMaskstr, &srcMask);
    inet_pton(AF_INET, dstIPstr, &dstIP);
    inet_pton(AF_INET, dstMaskstr, &dstMask);

    // Creación del nuevo filtro (lo pongo al principio de la lista; da igual porque luego se va a ordenar)
    filter_t *newFilter = (filter_t *) malloc(sizeof(filter_t));
    if (!newFilter) {
        fprintf(stderr, "DSTries_add_filter: error reservando memoria para filter_t");
        return -1;
    }
    filterList_t *newElto = (filterList_t *) malloc(sizeof(filterList_t));
    if (!newElto) {
        fprintf(stderr, "DSTries_add_filter: error reservando memoria para filterList_t");
        return -1;
    }
    
    newElto->filter = newFilter;
    newElto->next = NULL;
    newElto->prev = NULL;
    newFilter->id = id;
    newFilter->srcIP = srcIP;
    newFilter->srcMask = srcMask;
    newFilter->dstIP = dstIP;
    newFilter->dstMask = dstMask;
    if (*filterList) {
        (*filterList)->prev = newElto;
        newElto->next = *filterList;
    }
    *filterList = newElto;
    
    return 0;
}

// Nuevo árbol
dstNode_t *DSTries_new_tree() {
    dstNode_t *new = (dstNode_t *) calloc(1, sizeof(dstNode_t));
    
    if (!new) {
        fprintf(stderr, "DSTries_new_tree: error reservando memoria para dstNode_t");
        exit(-1);
    }
    new->id = dstID++;
    
    return new;
}

// Linka los nodos destino hijos con los filtros del padre.
static void DSTries_link_childs(dstNode_t *curDst, srcNode_t *ancestorSrcRoot, filter_t *filter) {
    if (!curDst || !ancestorSrcRoot || !filter) return;
    
    unsigned int srcIP = filter->srcIP;
    unsigned int srcMask = filter->srcMask;
    dstNode_t *child;
    srcNode_t *curSrc, *curAncSrc;
    int i, j;

    // para cada hijo, si existe
    for (i=0; i<TREEORDER; i++) {
        child = curDst->child[i];
        if (child) {
            curSrc = child->srcRoot;
            curAncSrc = ancestorSrcRoot;

            // Recorro el árbol de origen para linkar lo que falte
            if (curSrc) {
                for (j=0; j<TREEDEPTH && BIT(j, srcMask) && curSrc->dstID != curAncSrc->dstID; j++) {
                    // apunto al padre
                    if (!curSrc->ancestor) curSrc->ancestor = curAncSrc;
                    if (!curSrc->child[BIT(j, srcIP)]) {
                        // link y acabamos
                        curSrc->child[BIT(j, srcIP)] = curAncSrc->child[BIT(j, srcIP)];
                        break;
                    }
                    curSrc = curSrc->child[BIT(j, srcIP)];
                    curAncSrc = curAncSrc->child[BIT(j, srcIP)];
                }
                // apunto al padre
                if (curSrc->dstID != curAncSrc->dstID && !curSrc->ancestor) curSrc->ancestor = curAncSrc;
            } else child->srcRoot = ancestorSrcRoot;

            // Lo mismo para los hijos
            DSTries_link_childs(child, ancestorSrcRoot, filter);
        }
    }
}

// Inserta un filtro dado. Devuelve 1 en caso de éxito, 0 en caso contrario.
static int DSTries_insert_filter(dstNode_t *root, filter_t *filter) {
    if (!root || !filter) return 0;
    
    unsigned int srcIP = filter->srcIP;
    unsigned int srcMask = filter->srcMask;
    unsigned int dstIP = filter->dstIP;
    unsigned int dstMask = filter->dstMask;

    // Viajamos hasta el nodo más bajo
    dstNode_t *curDst = root;
    for (int i=0; i<TREEDEPTH && BIT(i, dstMask); i++) {
        if (!curDst->child[BIT(i, dstIP)]) {
            curDst->child[BIT(i, dstIP)] = (dstNode_t *) calloc(1, sizeof(dstNode_t));
            if (!curDst->child[BIT(i, dstIP)]) {
                fprintf(stderr, "DSTries_insert_filter: error reservando memoria para dstNode_t");
                return 0;
            }
            curDst->child[BIT(i, dstIP)]->id = dstID++;
        }
        curDst = curDst->child[BIT(i, dstIP)];
    }

    // Nuevo árbol de origen si no existía
    if (!curDst->srcRoot) {
        curDst->srcRoot = (srcNode_t *) calloc(1, sizeof(srcNode_t));
        if (!curDst->srcRoot) {
            fprintf(stderr, "DSTries_insert_filter: error reservando memoria para srcNode_t");
            return 0;
        }
        curDst->srcRoot->dstID = curDst->id;
    }

    // Viajamos hasta el nodo más bajo
    srcNode_t *curSrc = curDst->srcRoot;
    for (int i=0; i<TREEDEPTH && BIT(i, srcMask); i++) {
        if (!curSrc->child[BIT(i, srcIP)]) {
            curSrc->child[BIT(i, srcIP)] = (srcNode_t *) calloc(1, sizeof(srcNode_t));
            if (!curSrc->child[BIT(i, srcIP)]) {
                fprintf(stderr, "DSTries_insert_filter: error reservando memoria para srcNode_t");
                return 0;
            }
            curSrc->child[BIT(i, srcIP)]->dstID = curDst->srcRoot->dstID;
        }
        curSrc = curSrc->child[BIT(i, srcIP)];
    }

    // Registrar filtro y actualizar hijos
    if (!curSrc->filter) {
        //fprintf(stderr, "DEBUG_insert_pair: %i.%i.%i.%i srcIP\n", srcIP->byte[0], srcIP->byte[1], srcIP->byte[2], srcIP->byte[3]);
        curSrc->filter = filter;
        DSTries_link_childs(curDst, curDst->srcRoot, filter);
    }
    
    return 1;
}

// Ordena una lista de filtros de forma que las IPs de destino con prefijo mayor vayan primero.
static void DSTries_sort_filterList(filterList_t **head) {
    if (!*head) return;
    
    filterList_t *cur, *aux, *back;
    
    cur = (*head)->next;
    while (cur) {
        back = cur;
        while (back->prev && back->prev->filter->dstMask < cur->filter->dstMask) back = back->prev;
        if (back != cur) {
            // saco cur de la lista
            aux = cur;
            cur = aux->prev;
            cur->next = aux->next;
            if (cur->next) cur->next->prev = cur;

            // inserto antes que back
            aux->prev = back->prev;
            if (aux->prev) aux->prev->next = aux;
            aux->next = back;
            back->prev = aux;
        }
        // siguientes
        cur = cur->next;
    }
    
    while ((*head)->prev) *head = (*head)->prev;
}

// Inserta una lista de filtros dada. Devuelve 1 en caso de éxito, 0 en caso contrario.
int DSTries_insert_filterList(dstNode_t *root, filterList_t **filterList) {
    if (!root || !*filterList) return 0;
    
    int flag=1;
    DSTries_sort_filterList(filterList);
    
    filterList_t *elto = *filterList;
    while (elto) {
        flag = flag & DSTries_insert_filter(root, elto->filter);
        elto = elto->next;
    }
    
    return flag;
}

// Función para filtrar por un par de IPs. Para todos aquellos filtros que se verifican, se ejecuta la función de callback. Devuelve el número de filtros que se verifican.
int DSTries_filter(dstNode_t *root, void *header, const u_char *bytes, DSTries_IP_extract extractor, DSTries_callback callback, void *args) {
    if (!root || !header || !bytes || !extractor) return -1;
    
    unsigned int srcIP, dstIP;
    int success = extractor(header, bytes, &srcIP, &dstIP);
    if (!success) return -1;

    dstNode_t *curDst = root;
    srcNode_t *ancestor;
    int numFiltros = 0;

    // Viajamos hasta el nodo más bajo
    for (int i=0; i<TREEDEPTH+1; i++) {
        if (!curDst->child[BIT(i, dstIP)]) break;
        else curDst = curDst->child[BIT(i, dstIP)];
    }

    // Viajamos hasta el nodo más bajo
    srcNode_t *curSrc = curDst->srcRoot;
    if (!curSrc) return numFiltros;
    for (int i=0; i<TREEDEPTH+1; i++) {
        // callbacks
        if (curSrc->filter) {
            //fprintf(stderr, "DEBUG_filter: COINCIDENCIA %i\n", curSrc->filter->id);
            numFiltros++;
            if (callback) callback(args, curSrc->filter->id);
        }
        ancestor = curSrc->ancestor;
        while (ancestor) {
            //fprintf(stderr, "DEBUG_filter: %i\n", ancestor->dstID);
            if (ancestor->filter) {
                //fprintf(stderr, "DEBUG_filter: COINCIDENCIA %i\n", curSrc->filter->id);
                numFiltros++;
                if (callback) callback(args, ancestor->filter->id);
            }
            ancestor = ancestor->ancestor;
        }
        // siguiente
        curSrc = curSrc->child[BIT(i, srcIP)];
        if (!curSrc) break;
    }
    
    return numFiltros;
}

static void DSTries_destroy_subtree(srcNode_t *root) {
    if (!root) return;
    
    unsigned int id = root->dstID;
    for (int i=0; i<TREEORDER; i++) {
        if (root->child[i] && root->child[i]->dstID == id) DSTries_destroy_subtree(root->child[i]);
    }
    
    free(root);
}

// Destructor. Libera toda la estructura, pero no los filtros.
void DSTries_destroy_tree(dstNode_t *root) {
    if (!root) return;
    
    for (int i=0; i<TREEORDER; i++)
        DSTries_destroy_tree(root->child[i]);
    if (root->srcRoot && root->id == root->srcRoot->dstID)
        DSTries_destroy_subtree(root->srcRoot);

    free(root);
}

// Destructor. Libera toda la estructura junto con los filtros.
void DSTries_destroy_filterList(filterList_t *filterList) {
    if (!filterList) return;
    
    filterList_t *aux;
    while (filterList) {
        free(filterList->filter);
        aux = filterList;
        filterList = filterList->next;
        free(aux);
    }
}
