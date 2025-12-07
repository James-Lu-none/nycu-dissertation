# 12/08


## 比起讓產生LLM生成seed，讓LLM生成產生seeds的code

1. LLM 產的 seed generation code 本身可能不正確
2. LLM 會變成學到的是如何寫 seed generation code，不是如何針對漏洞產生特定輸入 (多了一層抽象)
3. 

## 我在猶豫的點

1. 我的目標應用是甚麼: 
Application-level? C++ level? OS level?

- Sanitizer 是 Memory Safety Bug
適用：C/C++, Memory corruption, Pointer bug, Overflow / UAF, Native code fuzzing
- Application-level XSS / SQLi 是 Semantic Security Bug
適用：Web apps, API, DB, Injection attack, Escape failure, Logic flaws, Sanitization bypass

1. 有兩個方向: 一個是做一個fuzzer框架，一個是做一個exploit框架
第一個就是我要讓LLM產生 new seed(丟)，第二個是讓LLM產生 exploit code

2. input output format
如果是fuzzer框架
input: 程式碼 + Approximate path constraints + Sanitizer的插樁 + 目前 seed set + 目前seed到達的constraints
output: 判斷CWE + 新seed

如果是exploit框架
input: 程式碼 + 漏洞位置 + 目前seed set
output: exploit code

3. 要如何有效的針對特定弱點進行變異? 這邊只能用prompt engineering? 還是說有可能可以提高這邊的解釋性?

整理一份 CWE 類別 -> 典型輸入變異策略 對照表
ex: 
CWE-119/120 (Buffer Overflow): 在特定欄位放超長 payload 使用重複 pattern AAAA....
CWE-79 (Cross-Site Scripting): 注入常見 XSS payloads 如 <script>alert(1)</script>

4. 要如何形成一個強力的feedback loop
