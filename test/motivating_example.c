#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// ---------------------------------------------------------
// 目標函數 (Target Function)
// ---------------------------------------------------------
void trigger_bug(char *input) {
    // 【陷阱 1：無效的分支 (Irrelevant Branch)】
    // 傳統 CFG 演算法 (AFLGo) 會在這裡給予權重，導致 Fuzzer 分心。
    // 但你的 PDF 演算法會發現它不是 Target 的門鎖，直接「忽略不插樁」。
    if (input[2] == 'X') {
        // 做一些無關緊要的事
        input[2] = 'Y';
    } else {
        input[2] = 'Z';
    }

    // 【門鎖 2：Intra-procedural ControlBB】
    // 你的 LLVM Pass 會透過 TargetBB 的 PDF 精準定位到這個 if 條件。
    if (input[3] == 'P') {
        
        // 💥 【目標：TargetBB】
        // 這是你一開始餵給 Pass 的目標節點！
        printf("BOOM! 漏洞觸發！\n");
        abort(); 
    }
}

// ---------------------------------------------------------
// 安全函數 (Safe Function) - 作為雜訊
// ---------------------------------------------------------
void safe_do_nothing() {
    volatile int x = 0;
    x++;
}

// ---------------------------------------------------------
// 分派器函數 (Dispatcher Function)
// ---------------------------------------------------------
void dispatcher(char *input) {
    // 【門鎖 1：Inter-procedural CallerBB 的 PDF】
    // 這是 DAFL 絕對解不開的死穴，因為 action_code 跟漏洞沒有資料流 (Data-flow) 關係。
    // 你的 Pass 跨程序追溯到 CallerBB 後，會算出這個 switch 是控制生死的外層門鎖！
    char action_code = input[1];
    switch (action_code) {
        case 'A':
            safe_do_nothing();
            break;
        case 'B':
            // 【跳板：CallerBB】
            // 這是呼叫目標函數的 CallSite。
            trigger_bug(input);
            break;
        case 'C':
            safe_do_nothing();
            break;
        default:
            break;
    }
}

// ---------------------------------------------------------
// 主函數 (Main Function)
// ---------------------------------------------------------
int main(int argc, char **argv) {
    char input[10] = {0};
    
    // 從標準輸入讀取資料 (AFL++ 的標準玩法)
    if (read(0, input, 8) < 4) {
        return 0;
    }

    // 【陷阱 2：迴圈陷阱 (Loop Trap)】
    // 傳統 DBB 或 CFG 演算法會被這個迴圈徹底搞暈，算出錯誤的距離。
    // 你的 Pass 因為只看 PDF，會直接無視這個迴圈，保持極致輕量！
    int checksum = 0;
    for (int i = 0; i < 100; i++) {
        if (input[0] == 'M') {
            checksum += i;
        }
    }

    // 進入分派器
    if (checksum > 0) {
        dispatcher(input);
    }

    return 0;
}