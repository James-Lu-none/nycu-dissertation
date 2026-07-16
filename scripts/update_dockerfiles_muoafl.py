import os
import glob
import re

def process_dockerfiles(root_dir):
    pattern = os.path.join(root_dir, "bench", "*", "Dockerfile")
    dockerfiles = glob.glob(pattern)
    for df_path in dockerfiles:
        with open(df_path, 'r') as f:
            content = f.read()

        # Remove ARG MUOAFL_TAG
        content = re.sub(r"ARG MUOAFL_TAG.*?\n", "", content)

        # Extract the dd-muoafl-build stage
        match = re.search(r"(FROM \$\{REGISTRY\}/muoafl:\$\{MUOAFL_TAG\} AS dd-muoafl-build\n.*?)(?=\n# Final Stage)", content, flags=re.DOTALL)
        if not match:
            print(f"Skipping {df_path}, dd-muoafl-build not found.")
            continue
            
        stage_content = match.group(1)
        
        # Replace the original stage with 3 stages
        new_stages = []
        for v in ["v1", "v2", "v3"]:
            stage = stage_content.replace("dd-muoafl-build", f"dd-muoafl-{v}-build")
            stage = stage.replace("${MUOAFL_TAG}", v)
            stage = f"# Stage: dd-muoafl-{v}-build\n" + stage
            new_stages.append(stage)
            
        replacement_stages = "\n".join(new_stages) + "\n"
        
        # Replace the original stage in the content
        content = content.replace(stage_content, replacement_stages)
        
        # Replace COPY block
        copy_lines = [line for line in content.splitlines() if line.startswith("COPY --from=dd-muoafl-build")]
        if len(copy_lines) == 2:
            original_copy_block = copy_lines[0] + "\n" + copy_lines[1]
            new_copy_blocks = []
            for v in ["v1", "v2", "v3"]:
                block = original_copy_block.replace("dd-muoafl-build", f"dd-muoafl-{v}-build")
                block = block.replace("-dd-muoafl", f"-dd-muoafl-{v}")
                new_copy_blocks.append(f"# Copy dd-muoafl-{v}-build output\n" + block)
            
            header_pattern = r"# Copy dd-muoafl-build output[^\n]*\n"
            content = re.sub(header_pattern + re.escape(original_copy_block), "\n".join(new_copy_blocks), content)
            
            # fallback
            if original_copy_block in content:
                content = content.replace(original_copy_block, "\n".join(new_copy_blocks))
                
        with open(df_path, 'w') as f:
            f.write(content)
        print(f"Updated {df_path}")

if __name__ == "__main__":
    process_dockerfiles("/home/user/workspace/nycu-dissertation")
