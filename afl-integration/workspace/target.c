#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void process_data(char *buf, size_t len)
{
    // 邏輯層級 1: 檢查長度
    if (len >= 4)
    {
        // 邏輯層級 2: 檢查前四個字元是否為 "FLAM"
        if (buf[0] == 'F' && buf[1] == 'L' && buf[2] == 'A' && buf[3] == 'M')
        {

            printf("Found the magic header!\n");

            // 邏輯層級 3: 潛在的漏洞點
            // 如果輸入長度在特定區間，我們會故意造成 Buffer Overflow
            if (len > 10 && len < 20)
            {
                char small_stack[8];
                printf("Triggering overflow...\n");
                // 漏洞：將 len 長度的資料拷貝到只有 8 bytes 的空間
                memcpy(small_stack, buf, len);
            }

            // 邏輯層級 4: 另一個崩潰路徑 (Null Pointer)
            if (buf[4] == '!')
            {
                printf("Target hit!\n");
                char *ptr = NULL;
                *ptr = 'X';
            }
        }
    }
}

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        printf("Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    // 模擬從檔案讀取輸入 (對應你的 @@ 指令)
    FILE *f = fopen(argv[1], "rb");
    if (!f)
    {
        perror("fopen");
        return 1;
    }

    // 取得檔案大小
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *buf = malloc(len);
    if (!buf)
        return 1;

    fread(buf, 1, len, f);
    fclose(f);

    // 進入處理邏輯
    process_data(buf, len);

    free(buf);
    return 0;
}