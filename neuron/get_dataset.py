import csv
import json
import os
import sys

csv.field_size_limit(sys.maxsize)

def parse_patch(patch_text):
    """
    從 Git Patch 中還原出「修改前 (Vulnerable)」與「修改後 (Benign)」的程式碼片段
    """
    vul_lines = []
    ben_lines = []
    
    for line in patch_text.split('\n'):
        if line.startswith('@@'):
            continue
        elif line.startswith('-'):
            vul_lines.append(line[1:])  # 漏洞代碼有這行
        elif line.startswith('+'):
            ben_lines.append(line[1:])  # 安全代碼有這行
        elif line.startswith(' '):
            vul_lines.append(line[1:])  # 雙方都有這行 (Context)
            ben_lines.append(line[1:])
        else:
            if line:
                vul_lines.append(line)
                ben_lines.append(line)
                
    return '\n'.join(vul_lines), '\n'.join(ben_lines)

def main():
    csv_file = "/home/user/workspace/MSR_20_Code_vulnerability_CSV_Dataset/all_c_cpp_release2.0.csv"
    out_dir = "/home/user/workspace/nycu-dissertation/neuron/dataset"
    
    vul_out = open(os.path.join(out_dir, "vulnerable.jsonl"), "w")
    ben_out = open(os.path.join(out_dir, "benign.jsonl"), "w")
    
    target_cwe = "CWE-119" # 鎖定 Buffer Overflow
    count = 0
    max_samples = 100 # 先取 100 筆測試
    
    print(f"Reading dataset: {csv_file}")
    with open(csv_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if target_cwe in row.get('cwe_id', ''):
                files_changed_str = row.get('files_changed', '')
                if not files_changed_str:
                    continue
                
                try:
                    # CSV 裡的 JSON 字串有些格式不完美，嘗試解析
                    files_changed = json.loads(files_changed_str)
                    
                    # 確保它是一個 list，如果只有一個檔案可能是 dict
                    if isinstance(files_changed, dict):
                        files_changed = [files_changed]
                        
                    for file_info in files_changed:
                        if 'patch' in file_info and file_info['patch']:
                            patch = file_info['patch']
                            vul_code, ben_code = parse_patch(patch)
                            
                            # 寫入 JSONL
                            vul_out.write(json.dumps({"id": row['cve_id'], "code": vul_code}) + '\n')
                            ben_out.write(json.dumps({"id": row['cve_id'], "code": ben_code}) + '\n')
                            
                            count += 1
                            if count >= max_samples:
                                break
                except Exception as e:
                    pass # 忽略解析錯誤的 JSON
                    
            if count >= max_samples:
                break

    vul_out.close()
    ben_out.close()
    print(f"Successfully extracted {count} pairs of {target_cwe} vulnerabilities.")

if __name__ == "__main__":
    main()
