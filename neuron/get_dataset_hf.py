import os
import json
from datasets import load_dataset
from tqdm import tqdm

def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    out_dir = os.path.join(base_dir, "dataset")
    os.makedirs(out_dir, exist_ok=True)
    
    vul_out = open(os.path.join(out_dir, "vulnerable.jsonl"), "w")
    ben_out = open(os.path.join(out_dir, "benign.jsonl"), "w")
    
    print("Downloading and Loading Hugging Face BigVul dataset (bstee615/bigvul)...")
    ds = load_dataset("bstee615/bigvul", split="train")
    
    target_cwe = "CWE-119"
    max_samples = 2000
    count = 0
    
    print(f"Filtering dataset for {target_cwe} and extracting valid function pairs...")
    
    for row in tqdm(ds, desc="Processing rows"):
        cwe_id = row.get("CWE ID", "")
        if cwe_id is None:
            continue
            
        if target_cwe in cwe_id:
            # targets C language specifically
            if row.get("lang", "").upper() != "C":
                continue
                
            func_before = row.get("func_before", "")
            func_after = row.get("func_after", "")
            
            if not func_before or not func_after:
                continue
                
            if func_before.strip() == func_after.strip():
                continue
                
            vul_out.write(json.dumps({"id": row.get("CVE ID", ""), "code": func_before}) + '\n')
            ben_out.write(json.dumps({"id": row.get("CVE ID", ""), "code": func_after}) + '\n')
            
            count += 1
            if count >= max_samples:
                break
                
    vul_out.close()
    ben_out.close()
    print(f"Extracted {count} function pairs of {target_cwe}")

if __name__ == "__main__":
    main()
