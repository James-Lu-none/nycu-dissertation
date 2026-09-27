import os
import csv
import json
import sys

csv.field_size_limit(sys.maxsize)

def parse_patch(patch_str):
    vul_lines = []
    ben_lines = []
    
    lines = patch_str.split('\n')
    for line in lines:
        if line.startswith('---') or line.startswith('+++'):
            continue
        elif line.startswith('@@'):
            continue
        elif line.startswith('-'):
            vul_lines.append(line[1:])
        elif line.startswith('+'):
            ben_lines.append(line[1:])
        elif line.startswith(' '):
            vul_lines.append(line[1:])  
            ben_lines.append(line[1:])
        else:
            if line:
                vul_lines.append(line)
                ben_lines.append(line)
                
    return '\n'.join(vul_lines), '\n'.join(ben_lines)

def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    csv_file = os.environ.get("CSV_FILE", os.path.join(base_dir, "..", "..", "MSR_20_Code_vulnerability_CSV_Dataset", "all_c_cpp_release2.0.csv"))
    out_dir = os.path.join(base_dir, "dataset")
    
    vul_out = open(os.path.join(out_dir, "vulnerable.jsonl"), "w")
    ben_out = open(os.path.join(out_dir, "benign.jsonl"), "w")
    
    target_cwe = "CWE-119" # 我們必須鎖定單一漏洞，否則方向向量會變成雜訊！
    count = 0
    max_samples = 1000
    
    print(f"Reading dataset: {csv_file}")
    with open(csv_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if target_cwe not in row.get('cwe_id', ''):
                continue
                
            files_changed_str = row.get('files_changed', '')
            if not files_changed_str:
                continue
            
            try:
                files_changed = json.loads(files_changed_str)
                if isinstance(files_changed, dict):
                    files_changed = [files_changed]
                    
                for file_info in files_changed:
                    if 'patch' in file_info and file_info['patch']:
                        patch = file_info['patch']
                        vul_code, ben_code = parse_patch(patch)
                        
                        vul_out.write(json.dumps({"id": row.get('cve_id', ''), "code": vul_code}) + '\n')
                        ben_out.write(json.dumps({"id": row.get('cve_id', ''), "code": ben_code}) + '\n')
                        
                        count += 1
                        if count % 50 == 0:
                            print(f"Extracted: {count}")
                        if count >= max_samples:
                            break
            except Exception as e:
                pass 
                
            if count >= max_samples:
                break

    vul_out.close()
    ben_out.close()
    print(f"Done. Final total count for {target_cwe}: {count}")

if __name__ == "__main__":
    main()
