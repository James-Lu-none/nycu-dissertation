#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "cJSON.h"
#include "cJSON_Utils.h"

extern uint8_t  *__afl_fuzz_ptr;
extern uint32_t *__afl_fuzz_len;

// 輔助函數：從 fuzz 資料中切出一段字串
static char *pick_string(const uint8_t **data, size_t *size, size_t len)
{
    if (*size < len || len == 0)
        return NULL;
    char *s = (char *)malloc(len + 1);
    if (!s)
        return NULL;
    memcpy(s, *data, len);
    s[len] = '\0';
    *data += len;
    *size -= len;
    return s;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    __afl_fuzz_ptr = (uint8_t *)data;
    static uint32_t current_size;
    current_size = (uint32_t)size;
    __afl_fuzz_len = &current_size;
    
    if (size < 5)
        return 0;

    // 將資料切分為兩部分：一半給基礎 JSON，一半給操作指令（如 Patch 路徑）
    size_t json_part_size = size / 2;
    char *json_str = pick_string(&data, &size, json_part_size);
    if (!json_str)
        return 0;

    // 1. 測試解析
    cJSON *root = cJSON_Parse(json_str);
    if (root)
    {
        // --- 測試區塊 1: 序列化 ---
        char *out = cJSON_Print(root);
        if (out)
            free(out);

        char *out_u = cJSON_PrintUnformatted(root);
        if (out_u)
            free(out_u);

        // --- 測試區塊 2: cJSON_Utils 功能 ---
        // 剩餘的 data 用來當作 JSON Pointer 或 Patch 內容
        if (size > 0)
        {
            char *extra_str = pick_string(&data, &size, size);
            if (extra_str)
            {
                // A. 測試 GetPointer
                cJSON *found = cJSONUtils_GetPointer(root, extra_str);

                // B. 測試 Patch
                cJSON *patch = cJSON_Parse(extra_str);
                if (patch)
                {
                    // 測試 ApplyPatches
                    cJSONUtils_ApplyPatches(root, patch);

                    // 測試 MergePatch (注意：MergePatch 可能返回新指標)
                    cJSON *merged = cJSONUtils_MergePatch(cJSON_Duplicate(root, 1), patch);
                    if (merged)
                        cJSON_Delete(merged);

                    cJSON_Delete(patch);
                }
                free(extra_str);
            }
        }

        // --- 測試區塊 3: 結構操作 (使用 1.3.0 相容語法) ---
        // 檢查是否為 Array (用 type bit mask)
        if ((root->type & 0xFF) == cJSON_Array && cJSON_GetArraySize(root) > 0)
        {
            cJSON_DeleteItemFromArray(root, 0);
        }
        // 檢查是否為 Object
        else if ((root->type & 0xFF) == cJSON_Object && root->child)
        {
            cJSONUtils_SortObject(root);
            if (root->child->string)
            {
                cJSON_DeleteItemFromObject(root, root->child->string);
            }
        }

        cJSON_Delete(root);
    }

    free(json_str);
    return 0;
}