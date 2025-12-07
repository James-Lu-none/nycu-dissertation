# report record
  
## 11/24
你拿soruce code塞跟你拿path constrain塞llm直接問他哪裡會有roadblock好像都沒有什麼學問
如果security 的issue加進去的話，你覺得會變怎麼樣? 如果把現在的collectiveness的東西換成security的檢測，從一般的verification換成security的verification
另外一個點是data privacy，code裡面會不會有privacy disclosure的問題
security oriented, privacy oriented, collectiveness oriented 作法都一樣，只是目標不同，
把程式碼丟到系統做檢測，然後還可以測他安全不安全，除了測他的 code coverage 之外

## TACC 12/01
Fuzzing Test 的目標是什麼? (過去作法可能是產生100%coverage的test cases，然後看 test 會不會當掉或者是看有沒有達成什麼目標)，如果你test是要看有沒有觸發弱點，那弱點的定義要明確
要fuzz哪種應用? 哪種程式語言?
與其讓產生LLM生成input，不如讓LLM生成產生input的code

## 12/08
如果DFA 知道哪個 input byte 控制 idx 跟 size 是多少，那好像跟我的基於LLM的弱點導向變異就沒什麼結合意義了
