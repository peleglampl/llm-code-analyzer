import argparse
import subprocess
import re

keywords = ["vulnerability", "buffer overflow", "stack overflow", "uninitialized variable", "memory leak",
            "corruption", "security issue", "UAF", "use after free", "dangling pointer", "heap overflow",
            "integer overflow", "memory leak", "segmentation fault", "double free", "format string attack",
            "race condition", "command injection", "null pointer dereference", "out of bounds access",
            "recursion overflow", "use after free", "dangling"]

def get_file_path_from_cli():
    """
    Get the file path of a C or C++ file from command line arguments.
    Returns:
        str: The path to the C or C++ file.
    """
    parser = argparse.ArgumentParser(description='Analyze a C or C++ file for vulnerabilities.')
    parser.add_argument('file_path', type=str, help='Path to the C or C++ file to analyze')
    args = parser.parse_args()
    return args.file_path


def read_file(file_path):
    """
    Reads the given C or C++ file and print its content, and returns the content as a list of lines.

    Args:
        file_path (str): The path to the C or C++ file.
    """
    try:
        with open(file_path, 'r') as file:
            content = file.readlines()
            # print(f"Content of {file_path}:\n")
            # print(content)
            return content
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return []


def split_into_chunks(lines, chunk_size=15):
    """
    Splits the list of lines into chunks of a specified size and prints each chunk.
    :param lines:
    :param chunk_size:
    :return:
    """
    chunk_arr = []
    for i in range(0, len(lines), chunk_size):
        chunk = lines[i:i + chunk_size]
        chunk_arr.append((chunk, i + 1))
    return chunk_arr


def build_prompt(snippet):
    """
    Build a prompt for the Phi model based on the code snippet.

    Args:
        snippet (list): A list of lines representing the code snippet.

    Returns:
        str: The formatted prompt for the Phi model.
    """

    code = ''.join(snippet)
    prompt = (
            "Analyze the following C or C++ code snippet for potential vulnerabilities:\n\n"
            "(e.g buffer overflow, use of uninitialized variables, etc.)\n\n" + code +
            "\n\nPlease provide a summary of any vulnerabilities found."
    )
    return prompt


def query_phi_model(prompt):
    """
    Query the Phi model with the given prompt and return the output.

    Args:
        prompt (str): The prompt to send to the Phi model.

    Returns:
        str: The output from the Phi model.
    """
    try:
        result = subprocess.run(
            ["ollama", "run", "phi"],
            input=prompt.encode(),
            capture_output=True,
            timeout=60
        )
        return result.stdout.decode()
    except Exception as e:
        return f"Error querying Phi model: {e}"


def is_vulnerability_detected(output):
    """
    Check if the output from the Phi model contains keywords indicating a vulnerability.
    :param output:
    :return:
    """
    if "i am an ai language model" in output or "i'm sorry" in output:
        return False

    if "does not contain any obvious vulnerabilities" in output:
        return "No obvious vulnerabilities."

    return any(k in output.lower() for k in keywords)


import re

def extract_summary(output):
    """
    Extracts a brief 1-sentence summary from the model's output.
    Skips generic LLM replies and preserves original casing.
    """
    output = output.strip()
    if not output:
        return None

    # Only used for filtering junk
    lower = output.lower()
    if "i am an ai language model" in lower or "i'm sorry" in lower:
        return None

    # Extract the first sentence (brief summary)
    match = re.match(r"^(.*?[.?!])(\s|$)", output)
    if match:
        return match.group(1).strip()

    # Fallback: truncate cleanly if needed
    return output[:150].strip() + "..." if len(output) > 150 else output



import json

def export_to_json(results, filename="analysis_results.json"):
    """
    Export the analysis results to a JSON file.

    Args:
        results (list): List of dictionaries with analysis data.
        filename (str): The filename to write the JSON to.
    """
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        print(f"\n📄 Full analysis saved to: {filename}")
    except Exception as e:
        print(f"❌ Error saving JSON file: {e}")



def main():
    summary = " "
    results = []
    file_path = get_file_path_from_cli()
    lines = read_file(file_path)
    snippets = split_into_chunks(lines, chunk_size=10)

    for snippet_lines, line_start in snippets:
        #print(f"\n--- Analyzing lines {line_start}-{line_start + len(snippet_lines) - 1} ---")
        prompt = build_prompt(snippet_lines)
        output = query_phi_model(prompt)
        if is_vulnerability_detected(output):
            summary = extract_summary(output)
            if summary:
                print(f"⚠️ Line {line_start}: {summary}")
            else:
                print(f"✅ Line {line_start}: No issue detected.")
        # else:
        #     print("✅ No issue detected.")

        results.append({
            "start_line": line_start,
            "end_line": line_start + len(snippet_lines) - 1,
            "summary": summary or "No issue detected.",
            "details": output.strip()  # full LLM output
        })

    export_to_json(results, filename="analysis_results.json")


if __name__ == "__main__":
    main()
