import random
import os

class LLMMutator:
    def __init__(self):
        # 這裡可以初始化你的 LLM Client (例如 OpenAI API 或連線到本地 GPU Server)
        self.model_name = "Mock-LLM-v1"
        print(f"[LLM Mutator] {self.model_name} initialized.")

    def mutate(self, buf):
        """
        buf: 原始的 testcase 資料 (bytes)
        回傳: 變異後的資料 (bytes)
        """
        # --- 這裡是你未來要實作 LLM 邏輯的地方 ---
        # 1. 讀取 DFSan 傳遞過來的 Taint/Path 資訊 (例如透過 SHM 或文件)
        # 2. 組合 Prompt
        # 3. 呼叫 LLM 獲取 Mutation Operator (例如: "flip bit at offset 5")
        
        # 範例：Mock LLM 決策 - 隨機在末尾增加一個位元組
        data = bytearray(buf)
        data.append(random.randint(0, 255))
        
        return bytes(data)

# 全域變數供 AFL++ 呼叫
mutator = None

def init(seed):
    """ AFL++ 初始化時呼叫一次 """
    global mutator
    mutator = LLMMutator()
    # seed 是隨機數種子，可用於保持實驗可重複性
    random.seed(seed)

def afl_custom_fuzz(buf, add_buf, max_size):
    """
    這是核心 Hook。AFL++ 每執行一次自定義變異都會進來這裡。
    buf: 當前的 Input
    add_buf: 來自其他 Testcase 的數據 (crossover 用)
    max_size: 緩衝區上限
    """
    global mutator
    # 呼叫我們的變異邏輯
    mutated_data = mutator.mutate(buf)
    
    # 確保長度不超過 AFL++ 限制
    return mutated_data[:max_size]

def afl_custom_fuzz_count(buf):
    """
    決定一個 Seed 要經過幾次這個自定義變異。
    由於 LLM 很慢，建議先設為 1。
    """
    return 1

def afl_custom_post_process(buf):
    """
    可選：在寫入硬碟前對數據進行最後處理 (如修復 Checksum)
    """
    return buf