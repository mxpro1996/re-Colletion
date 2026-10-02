#include <stdio.h>
#include <stdint.h> 
#include <stdlib.h> 

static void nibble_swap(uint8_t *buf, size_t len) 
{ 
    size_t i; 
    for (i = 0; i < len; ++i) 
     buf[i] = (uint8_t)((buf[i] >> 4) | (buf[i ] << 4));
} 
static int process_file(const char *input, const char *output) { 
    FILE *fin; FILE *fout; uint8_t buf[4096]; 
    size_t n; 
    
    fin = fopen(input,"rb"); 
    if (!fin) 
    { 
        perror("fopen input"); return 1;
    }
    fout = fopen(output,"wb"); 
    if (!fout) 
    { 
        perror("fopen output"); fclose(fin); return 1;
    } 
    while ((n = fread(buf, 1, sizeof(buf), fin)) > 0)
    { 
        nibble_swap(buf, n); 
        if (fwrite(buf,1, n, fout) != n) 
        { 
            perror("fwrite"); fclose(fout); fclose(fin); return 1;
        }
    } 
    
    if (ferror(fin)) { 
        perror("fread"); 
        fclose(fout); 
        fclose(fin); 
        return 1;
    } 
    fclose(fout); fclose(fin); return 0;
} 

int main(int argc, char **argv) { 
    if (argc != 3) 
    { 
        fprintf(stderr,"Usage: %s input output\n", argv[0]); 
        return 1;
    } 
    return process_file(argv[1], argv[2]);
}