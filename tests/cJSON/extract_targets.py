import csv
with open("security_results.csv", "r") as f:
    reader = csv.reader(f)
    with open("targets.csv", "w") as out:
        for row in reader:
            if len(row) >= 6:
                path = row[4].lstrip("/")
                line = row[5]
                out.write(f"{path},{line}\n")