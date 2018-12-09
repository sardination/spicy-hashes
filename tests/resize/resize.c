/**
 * Resizes a BMP
 */

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <stdlib.h>
#include <string.h>

#include <stdio.h>
#include "bmp.h"

int main(int argc, char *argv[])
{
    // ensure proper usage
    if (argc != 4)
    {
        return 1;
    }

    // ennsure valid scale
    int n = atoi(argv[1]);
    if (n < 1 || n > 100) {
        return 1;
    }

    // remember filenames
    char *infile = argv[2];
    char *outfile = argv[3];

    // open input file
    int inptr = open(infile, O_RDONLY);
    if (inptr == -1)
    {
        perror(NULL);
        return 2;
    }

    // open output file
    int outptr = open(outfile, O_WRONLY|O_CREAT|O_TRUNC, 0666);
    if (outptr == -1)
    {
        close(inptr);
        perror(NULL);
        return 3;
    }

    // read infile's BITMAPFILEHEADER
    BITMAPFILEHEADER bf;
    read(inptr, &bf, sizeof(BITMAPFILEHEADER));

    // read infile's BITMAPINFOHEADER
    BITMAPINFOHEADER bi;
    read(inptr, &bi, sizeof(BITMAPINFOHEADER));

    // ensure infile is (likely) a 24-bit uncompressed BMP 4.0
    if (bf.bfType != 0x4d42 || bf.bfOffBits != 54 || bi.biSize != 40 ||
        bi.biBitCount != 24 || bi.biCompression != 0)
    {
        close(outptr);
        close(inptr);
        return 4;
    }

    // save original dimensions for later
    int in_height = bi.biHeight;
    int in_width = bi.biWidth;

    // scale dimensions in header struct
    bi.biHeight *= n;
    bi.biWidth *= n;

    // determine padding for in and out scanlines
    int padding = (4 - (bi.biWidth * sizeof(RGBTRIPLE)) % 4) % 4;
    int in_padding = (4 - (in_width * sizeof(RGBTRIPLE)) % 4) % 4;

    // change other header info
    size_t line_size = bi.biWidth * sizeof(RGBTRIPLE) + padding; // used later
    bi.biSizeImage = line_size * abs(bi.biHeight);
    bf.bfSize = bi.biSizeImage + sizeof(BITMAPFILEHEADER)
                + sizeof(BITMAPINFOHEADER);

    // write outfile's BITMAPFILEHEADER
    write(outptr, &bf, sizeof(BITMAPFILEHEADER));

    // write outfile's BITMAPINFOHEADER
    write(outptr, &bi, sizeof(BITMAPINFOHEADER));

    // create line buffer for out file
    char *buffer = malloc(line_size);
    size_t pos = 0; // track position in buffer

    // iterate over infile's scanlines
    for (int i = 0, biHeight = abs(in_height); i < biHeight; i++)
    {
        // iterate over pixels in scanline
        for (int j = 0; j < in_width; j++)
        {
            // temp storage for buffer.  buffer buffer
            RGBTRIPLE triple;

            // read triple into temp storage
            read(inptr, &triple, sizeof(RGBTRIPLE));

            // move temp storage into buffer n times
            for (int k = 0; k < n; k++) {
                memcpy(&buffer[pos], &triple, sizeof(RGBTRIPLE));
                pos += sizeof(RGBTRIPLE);
            }
        }

        // skip over padding in infile, if any
        lseek(inptr, in_padding, SEEK_CUR);

        // add out padding to buffer
        for (int k = 0; k < padding; k++) buffer[pos++] = 0x0;

        // write line buffer to out file n times and reset pos
        for (int k = 0; k < n; k++) {
            write(outptr, buffer, line_size);
        }
        pos = 0;
    }

    // close infile
    close(inptr);

    // close outfile
    close(outptr);

    // free buffer(s)
    free(buffer);

    // success
    return 0;
}
