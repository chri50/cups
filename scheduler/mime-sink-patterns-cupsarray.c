/*
 * cupsArray-based implementation of printer sink pattern reuse.
 *
 * This file mirrors the logic in mime-sink-patterns.c but replaces the
 * fixed-size hash table with a cups_array_t-based cache using compare,
 * hash, copy and free callbacks so it can be compared side-by-side.
 */

#include "cupsd.h"
#include "mime-sink-patterns.h"
#include <cups/array.h>
#include <stdint.h>
#include <string.h>

/* FNV-1a hash constants */
#define FNV1A_32_INIT   0x811c9dc5u
#define FNV1A_32_PRIME  0x01000193u

/* Masks */
#define UINT32_MASK     0xFFFFFFFFU

/* Hash table size used for cupsArrayNew2/3 */
#define MSINK_ARR_HASH_SIZE 1024

/* Edge structure (same shape as the original file-local type) */
typedef struct msink_edge_s
{
    const char *super;
    const char *type;
    int cost;
    size_t maxsize;
    uint32_t prog_hash;
} msink_edge_t;

/* Entry stored in the cupsArray cache */
typedef struct msink_entry_s
{
    int edge_count;
    msink_edge_t *edges;
    cups_array_t *filetypes; /* mime_type_t* elements */
} msink_entry_t;

/* Global cups array for cache entries (lazily created) */
static cups_array_t *msink_arr = NULL;
static int msink_enabled_checked = 0;
static int msink_enabled = 0;

/*
 * 'msink_env_enabled()' - Check if feature is enabled via environment variable.
 */
static int
msink_env_enabled(void)
{
    if (!msink_enabled_checked)
    {
        const char *env_value = getenv("CUPS_MIME_SINK_REUSE");
        if (env_value &&
            (!_cups_strcasecmp(env_value, "1") ||
             !_cups_strcasecmp(env_value, "yes") ||
             !_cups_strcasecmp(env_value, "true") ||
             !_cups_strcasecmp(env_value, "on")))
        {
            msink_enabled = 1;
        }

        msink_enabled_checked = 1;

        cupsdLogMessage(CUPSD_LOG_INFO, "CUPS_MIME_SINK_REUSE=%s (%s)",
                        env_value ? env_value : "(unset)",
                        msink_enabled ? "enabled" : "disabled");
    }

    return msink_enabled;
}

int
msink_is_enabled(void)
{
    return msink_env_enabled();
}

/* Helpers (file-local copies of the algorithms used in the original file) */
static uint32_t
hash_str(const char *s)
{
    uint32_t hash = FNV1A_32_INIT;
    unsigned char c;
    while (s && (c = (unsigned char)*s++))
    {
        hash ^= c;
        hash *= FNV1A_32_PRIME;
    }
    return hash;
}

static int
edge_cmp(const void *a, const void *b)
{
    const msink_edge_t *edge_a = (const msink_edge_t *)a;
    const msink_edge_t *edge_b = (const msink_edge_t *)b;
    int diff;

    if ((diff = strcmp(edge_a->super, edge_b->super)) != 0)
        return diff;
    if ((diff = strcmp(edge_a->type, edge_b->type)) != 0)
        return diff;
    if (edge_a->cost != edge_b->cost)
        return edge_a->cost - edge_b->cost;
    if (edge_a->maxsize != edge_b->maxsize)
        return (edge_a->maxsize > edge_b->maxsize) ? 1 : -1;
    if (edge_a->prog_hash != edge_b->prog_hash)
        return (int)edge_a->prog_hash - (int)edge_b->prog_hash;
    return 0;
}

/* We use an on-the-fly hash callback below and don't need a separate
 * signature/sig field. */

static int
edges_equal(msink_edge_t *a, msink_edge_t *b, int count)
{
    int i;
    for (i = 0; i < count; i++)
    {
        if (strcmp(a[i].super, b[i].super) != 0 ||
            strcmp(a[i].type, b[i].type) != 0 ||
            a[i].cost != b[i].cost ||
            a[i].maxsize != b[i].maxsize ||
            a[i].prog_hash != b[i].prog_hash)
        {
            return 0;
        }
    }
    return 1;
}

/* cupsArray callbacks ---------------------------------------------------- */
static int
msink_arr_compare(void *a, void *b, void *user_data)
{
    msink_entry_t *ea = (msink_entry_t *)a;
    msink_entry_t *eb = (msink_entry_t *)b;

    if (ea->edge_count < eb->edge_count) return -1;
    if (ea->edge_count > eb->edge_count) return 1;

    /* Fast path: entries are equal if their edges match exactly */
    if (edges_equal(ea->edges, eb->edges, ea->edge_count))
        return 0;

    /* Otherwise produce a deterministic ordering using edges */
    for (int i = 0; i < ea->edge_count; i++)
    {
        int r = edge_cmp(&ea->edges[i], &eb->edges[i]);
        if (r < 0) return -1;
        if (r > 0) return 1;
    }

    /* They differ but all compared fields matched (shouldn't happen) - fall back to equal */
    return 0;
}

/* Hash callback - compute a simple 32-bit mix over all edge fields and
 * return modulo the hash size. This avoids building a separate sig field
 * and uses a lightweight multiply-add mix similar to ppd_hash_option. */
static int
msink_arr_hash(void *elem, void *user_data)
{
    msink_entry_t *e = (msink_entry_t *)elem;
    uint32_t hash = 5381u;

    for (int i = 0; i < e->edge_count; i++)
    {
        const msink_edge_t *edge = &e->edges[i];
        const unsigned char *s;

        /* Mix in super */
        for (s = (const unsigned char *)edge->super; s && *s; s++)
            hash = ((hash << 5) + hash) + *s; /* hash * 33 + c */

        /* Separator */
        hash = ((hash << 5) + hash) + 0xFF;

        /* Mix in type */
        for (s = (const unsigned char *)edge->type; s && *s; s++)
            hash = ((hash << 5) + hash) + *s;

        /* Separator */
        hash = ((hash << 5) + hash) + 0xFE;

        /* Mix in numeric fields */
        uint32_t mix = (uint32_t)edge->cost ^ (uint32_t)(edge->maxsize & UINT32_MASK) ^ edge->prog_hash;
        for (int b = 0; b < 4; b++)
            hash = ((hash << 5) + hash) + (unsigned char)((mix >> (b*8)) & 0xFF);
    }

    return (int)(hash % MSINK_ARR_HASH_SIZE);
}

static void *
msink_arr_copy(void *element, void *user_data)
{
    msink_entry_t *src = (msink_entry_t *)element;
    msink_entry_t *dst = (msink_entry_t *)calloc(1, sizeof(msink_entry_t));
    if (!dst) return NULL;
    dst->edge_count = src->edge_count;
    dst->edges = (msink_edge_t *)malloc(dst->edge_count * sizeof(msink_edge_t));
    if (dst->edges && src->edges)
        memcpy(dst->edges, src->edges, dst->edge_count * sizeof(msink_edge_t));
    else if (dst->edges == NULL)
    {
        free(dst);
        return NULL;
    }

    dst->filetypes = src->filetypes ? cupsArrayDup(src->filetypes) : NULL;

    return dst;
}

static void
msink_arr_free(void *element, void *user_data)
{
    msink_entry_t *e = (msink_entry_t *)element;
    if (!e) return;
    if (e->edges) free(e->edges);
    if (e->filetypes) cupsArrayDelete(e->filetypes);
    free(e);
}

/* Lazy initializer for the cupsArray cache */
static void
msink_arr_init(void)
{
    if (!msink_arr)
        msink_arr = cupsArrayNew3((cups_array_func_t)msink_arr_compare, NULL,
                                 (cups_ahash_func_t)msink_arr_hash, MSINK_ARR_HASH_SIZE,
                                 (cups_acopy_func_t)msink_arr_copy, (cups_afree_func_t)msink_arr_free);
}

/* Public API (prefixed to avoid collision with original functions) */

int
msink_reuse(mime_t *mime, mime_type_t *sink, cups_array_t **out_filetypes)
{
    if (out_filetypes) *out_filetypes = NULL;
    if (!mime || !sink) return 0;

    int cap = 8, acnt = 0;
    msink_edge_t *all = (msink_edge_t *)malloc(cap * sizeof(msink_edge_t));
    if (!all) return 0;

    mime_filter_t *flt;
    for (flt = mimeFirstFilter(mime); flt; flt = mimeNextFilter(mime))
    {
        if (flt->dst == sink)
        {
            if (acnt == cap)
            {
                cap *= 2;
                msink_edge_t *ne = (msink_edge_t *)realloc(all, cap * sizeof(msink_edge_t));
                if (!ne)
                {
                    free(all);
                    return 0;
                }
                all = ne;
            }
            all[acnt].super = flt->src->super;
            all[acnt].type = flt->src->type;
            all[acnt].cost = flt->cost;
            all[acnt].maxsize = flt->maxsize;
            all[acnt].prog_hash = hash_str(flt->filter);
            acnt++;
        }
    }
    if (acnt == 0)
    {
        free(all);
        return 0;
    }

    msink_edge_t *gen = (msink_edge_t *)malloc(acnt * sizeof(msink_edge_t));
    if (!gen)
    {
        free(all);
        return 0;
    }
    int gcnt = 0;
    for (int i = 0; i < acnt; i++)
    {
        gen[gcnt] = all[i];
        if (!_cups_strcasecmp(all[i].super, "printer"))
        {
            gen[gcnt].super = "printer";
            gen[gcnt].type = "sink";
        }
        gcnt++;
    }
    qsort(gen, gcnt, sizeof(msink_edge_t), edge_cmp);

    /* Ensure array exists */
    msink_arr_init();

    /* Prepare a temporary entry for lookup */
    msink_entry_t tmp;
    tmp.edge_count = gcnt;
    tmp.edges = gen; /* pointer used only for compare/hash - not owned */

    msink_entry_t *found = (msink_entry_t *)cupsArrayFind(msink_arr, &tmp);
    if (found)
    {
        if (out_filetypes && found->filetypes)
            *out_filetypes = cupsArrayDup(found->filetypes);

        free(gen);
        free(all);
        cupsdLogMessage(CUPSD_LOG_DEBUG2,
                        "sink-pattern-arr: cache hit edges=%d (printer/* normalized)",
                        gcnt);
        return 1;
    }

    free(gen);
    free(all);
    return 0;
}

void
msink_try_store(mime_t *mime, mime_type_t *sink, cups_array_t *filetypes)
{
    if (!mime || !sink || !filetypes) return;

    int cap = 8, cnt = 0;
    msink_edge_t *all = (msink_edge_t *)malloc(cap * sizeof(msink_edge_t));
    if (!all) return;

    mime_filter_t *flt;
    for (flt = mimeFirstFilter(mime); flt; flt = mimeNextFilter(mime))
    {
        if (flt->dst == sink)
        {
            if (cnt == cap)
            {
                cap *= 2;
                msink_edge_t *ne = (msink_edge_t *)realloc(all, cap * sizeof(msink_edge_t));
                if (!ne)
                {
                    free(all);
                    return;
                }
                all = ne;
            }
            all[cnt].super = flt->src->super;
            all[cnt].type = flt->src->type;
            all[cnt].cost = flt->cost;
            all[cnt].maxsize = flt->maxsize;
            all[cnt].prog_hash = hash_str(flt->filter);
            cnt++;
        }
    }
    if (cnt == 0)
    {
        free(all);
        return;
    }

    msink_edge_t *gen = (msink_edge_t *)malloc(cnt * sizeof(msink_edge_t));
    if (!gen)
    {
        free(all);
        return;
    }
    int gcnt = 0;
    for (int i = 0; i < cnt; i++)
    {
        gen[gcnt] = all[i];
        if (!_cups_strcasecmp(all[i].super, "printer"))
        {
            gen[gcnt].super = "printer";
            gen[gcnt].type = "sink";
        }
        gcnt++;
    }
    qsort(gen, gcnt, sizeof(msink_edge_t), edge_cmp);

    msink_arr_init();

    /* Prepare lookup entry */
    msink_entry_t tmp;
    tmp.edge_count = gcnt;
    tmp.edges = gen;

    /* If it already exists, nothing to do */
    if (cupsArrayFind(msink_arr, &tmp))
    {
        free(gen);
        free(all);
        return;
    }

    /* Create a new entry to add (we'll duplicate when adding to the array) */
    msink_entry_t ent;
    memset(&ent, 0, sizeof(ent));
    ent.edge_count = gcnt;
    ent.edges = gen; /* used by copy function when duplicating */
    ent.filetypes = cupsArrayDup(filetypes);

    /* Add to cupsArray (copy callback will duplicate ent) */
    cupsArrayAdd(msink_arr, &ent);

    /* Find the stored entry (use tmp which references ent.edges/gen which are still valid) */
    msink_entry_t *found = (msink_entry_t *)cupsArrayFind(msink_arr, &tmp);

    /* Log using the stored entry (found may be NULL in rare cases) */
    cupsdLogMessage(CUPSD_LOG_INFO, "sink-pattern-arr: store edges=%d supported=%d",
                    gcnt, found ? cupsArrayCount(found->filetypes) : 0);

    /* Free temporary resources: copy already duplicated by copy callback */
    if (ent.edges) free(ent.edges);
    if (ent.filetypes) cupsArrayDelete(ent.filetypes);
    free(all);
}

int
msink_try_reuse(cupsd_printer_t *printer)
{
    if (!printer) return 0;
    if (!msink_is_enabled()) return 0; /* reuse the existing feature switch */

    cups_array_t *reuse_filetypes = NULL;
    if (msink_reuse(MimeDatabase, printer->filetype, &reuse_filetypes))
    {
        printer->filetypes = reuse_filetypes;
        return 1;
    }
    return 0;
}
