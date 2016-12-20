#include <linux/kernel.h>
#include <linux/zlib.h>
#include <linux/slab.h>
// #include <linux/vmalloc.h>
/* Compress data */
int deflateCompress(Byte *data, uLong ndata,
                    Byte *zdata, uLong *nzdata)
{
    z_stream c_stream;
    int err = 0;

    if(data && ndata > 0)
    {
        // c_stream.zalloc = (alloc_func)0;
        // c_stream.zfree = (free_func)0;
        // c_stream.opaque = (voidpf)0;
        if(zlib_deflateInit(&c_stream, Z_DEFAULT_COMPRESSION) != Z_OK) return -1;
        c_stream.next_in  = data;
        c_stream.avail_in  = ndata;
        c_stream.next_out = zdata;
        c_stream.avail_out  = *nzdata;
        while (c_stream.avail_in != 0 && c_stream.total_out < *nzdata)
        {
            if(zlib_deflate(&c_stream, Z_NO_FLUSH) != Z_OK) return -1;
        }
        if(c_stream.avail_in != 0) return c_stream.avail_in;
        for (;;) {
            if((err = zlib_deflate(&c_stream, Z_FINISH)) == Z_STREAM_END) break;
            if(err != Z_OK) return -1;
        }
        if(zlib_deflateEnd(&c_stream) != Z_OK) return -1;
        *nzdata = c_stream.total_out;
        return 0;
    }
    return -1;
}

/* Uncompress data */
int deflateDeCompress(Byte *zdata, uLong nzdata,
                      Byte *data, uLong *ndata)
{
    int err = 0;
    z_stream d_stream; /* decompression stream */

    // d_stream.zalloc = (alloc_func)0;
    // d_stream.zfree = (free_func)0;
    // d_stream.opaque = (voidpf)0;
    d_stream.next_in  = zdata;
    d_stream.total_in = nzdata;
    d_stream.next_out = data;

    if(zlib_inflateInit(&d_stream) != Z_OK) return -1;
    while (d_stream.total_out < *ndata && d_stream.total_in < nzdata) {
        d_stream.avail_in = d_stream.avail_out = 1;  /* force small buffers */
        if((err = zlib_inflate(&d_stream, Z_NO_FLUSH)) == Z_STREAM_END) break;
        if(err != Z_OK) return -1;
    }
    if(zlib_inflateEnd(&d_stream) != Z_OK) return -1;
    *ndata = d_stream.total_out;
    return 0;
}

// ---------------------------------------------
/* Compress gzip data */
int gzipCompress(Byte *data, uLong ndata,
                 Byte *zdata, uLong *nzdata)
{
    z_stream c_stream;
    c_stream.workspace = kmalloc(zlib_deflate_workspacesize(MAX_WBITS, MAX_MEM_LEVEL), GFP_KERNEL);
    int err = 0;

    if(data && ndata > 0)
    {
        // c_stream.zalloc = (alloc_func)0;
        // c_stream.zfree = (free_func)0;
        // c_stream.opaque = (voidpf)0;
        if(zlib_deflateInit2(&c_stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                        -MAX_WBITS, 8, Z_DEFAULT_STRATEGY) != Z_OK) return -1;
        c_stream.next_in  = data;
        c_stream.avail_in  = ndata;

        c_stream.next_out = zdata;
        c_stream.avail_out  = *nzdata;

        while (c_stream.avail_in != 0 && c_stream.total_out < *nzdata)
        {
            if(zlib_deflate(&c_stream, Z_NO_FLUSH) != Z_OK) return -2;
        }
        if(c_stream.avail_in != 0) return c_stream.avail_in;
        for (;;) {
            if((err = zlib_deflate(&c_stream, Z_FINISH)) == Z_STREAM_END) break;
            if(err != Z_OK) return -3;
        }
        if(zlib_deflateEnd(&c_stream) != Z_OK) return -4;
        *nzdata = c_stream.total_out;
        return 0;
    }
    return -5;
}

/* Uncompress gzip data */
int gzipDeCompress(Byte *zdata, uLong nzdata,
                   Byte *data, uLong *ndata)
{
    int err = 0;
    z_stream d_stream; /* decompression stream */
    d_stream.workspace = kmalloc(zlib_inflate_workspacesize(), GFP_KERNEL);
    static char dummy_head[2] =
            {
                    0x8 + 0x7 * 0x10,
                    (((0x8 + 0x7 * 0x10) * 0x100 + 30) / 31 * 31) & 0xFF,
            };
    // d_stream.zalloc = (alloc_func)0;
    // d_stream.zfree = (free_func)0;
    // d_stream.opaque = (voidpf)0;
    d_stream.next_in  = zdata;
    d_stream.avail_in = nzdata;

    d_stream.next_out = data;
    d_stream.avail_out = *ndata;

    if(zlib_inflateInit2(&d_stream, -MAX_WBITS) != Z_OK) return -1;
    //if(zlib_inflateInit2(&d_stream, 47) != Z_OK) return -1;

    while (d_stream.total_out < *ndata && d_stream.total_in < nzdata) {
        d_stream.avail_in = d_stream.avail_out = 1; /* force small buffers */
        if((err = zlib_inflate(&d_stream, Z_NO_FLUSH)) == Z_STREAM_END) break;
        if(err != Z_OK )
        {
            if(err == Z_DATA_ERROR)
            {
                d_stream.next_in = (Byte*) dummy_head;
                d_stream.avail_in = sizeof(dummy_head);
                if((err = zlib_inflate(&d_stream, Z_NO_FLUSH)) != Z_OK)
                    return -2;
            }
            else
                return -3;
        }
    }
    if(zlib_inflateEnd(&d_stream) != Z_OK) {
        return -4;
    }
    *ndata = d_stream.total_out;
    kfree(d_stream.workspace);
    return 0;
}

/* HTTP gzip decompress */
int gzipHttpDeCompress(Byte *zdata, uLong nzdata,
                       Byte *data, uLong *ndata)
{
    int err = 0;
    z_stream d_stream = {0}; /* decompression stream */
    static char dummy_head[2] =
            {
                    0x8 + 0x7 * 0x10,
                    (((0x8 + 0x7 * 0x10) * 0x100 + 30) / 31 * 31) & 0xFF,
            };
    // d_stream.zalloc = (alloc_func)0;
    // d_stream.zfree = (free_func)0;
    // d_stream.opaque = (voidpf)0;
    d_stream.next_in  = zdata;
    d_stream.avail_in = nzdata;

    d_stream.next_out = data;
    d_stream.avail_out = *ndata;

    if(zlib_inflateInit2(&d_stream, 47) != Z_OK) return -1;
    while (d_stream.total_out < *ndata && d_stream.total_in < nzdata) {
        d_stream.avail_in = d_stream.avail_out = 1; /* force small buffers */
        if((err = zlib_inflate(&d_stream, Z_NO_FLUSH)) == Z_STREAM_END)
            break;
        if(err != Z_OK )
        {
            if(err == Z_DATA_ERROR)
            {
                d_stream.next_in = (Byte*) dummy_head;
                d_stream.avail_in = sizeof(dummy_head);
                if((err = zlib_inflate(&d_stream, Z_NO_FLUSH)) != Z_OK)
                {
                    return -1;
                }
            }
            else{
                return -1;
            }
        }
    }
    if(zlib_inflateEnd(&d_stream) != Z_OK)   return -1;
    *ndata = d_stream.total_out;
    return 0;
}