#include <zlib.h>

/* Compress data */
int deflateCompress(Bytef *data, uLong ndata,
              Bytef *zdata, uLong *nzdata);


/* Uncompress data */
int deflateDeCompress(Byte *zdata, uLong nzdata,
                      Byte *data, uLong *ndata);


// ---------------------------------------------
/* Compress gzip data */
int gzipCompress(Bytef *data, uLong ndata,
               Bytef *zdata, uLong *nzdata);


/* Uncompress gzip data */
int gzipDeCompress(Byte *zdata, uLong nzdata,
                   Byte *data, uLong *ndata);


/* HTTP gzip decompress */
int gzipHttpDeCompress(Byte *zdata, uLong nzdata,
                     Byte *data, uLong *ndata);
