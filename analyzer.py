import argparse
import subprocess
import json
import re

# List of keywords to identify vulnerabilities in the output from the Phi model.
keywords = ["vulnerability", "buffer overflow", "stack overflow", "uninitialized variable", "memory leak",
            "corruption", "security issue", "UAF", "use after free", "dangling pointer", "heap overflow",
            "integer overflow", "memory leak", "segmentation fault", "double free", "format string attack",
            "race condition", "command injection", "null pointer dereference", "out of bounds access",
            "recursion overflow", "use after free", "dangling"]

# General phrases that indicate the model is not providing a specific vulnerability or fix.
general_phrase = ["no known", "it's difficult to say", "there might be", "it could be", "this may indicate",
                  "there are no known vulnerabilities", "appears safe",
                  "i am an ai language model", "i'm sorry", "without seeing the code",
                  "difficult to provide", "there is no clear indication", "could include",
                  "does not contain any known vulnerabilities", "no known vulnerabilities",
                  "any vulnerabilities", "no obvious vulnerabilities", "doesn't appear to have",
                  "i am not capable of", "doesn't appear to have", "no issues detected",
                  "not found", "no issues detected", "no vulnerabilities", "no real vulnerability"]


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
            return content
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return []


def split_into_chunks(lines, chunk_size=7):
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
            "You are a security expert analyzing C/C++ code.\n"
            "Only respond if you detect a REAL vulnerability in the code snippet below.\n"
            "Do not speculate or guess. If no vulnerability is found, reply exactly: 'No issue detected.'\n\n"
            "Code:\n\n" + code + "\n\n"
                                 "If a vulnerability exists:\n"
                                 "- Provide a one-line summary.\n"
                                 "- Then write: Fix: <one-line fix>."
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
    Check if the output from the Phi model indicates a vulnerability.
    Args:
        output (str): The output from the Phi model.
    """
    output = output.lower()
    if (
        "error querying phi" in output or
        any(phrase in output for phrase in general_phrase)
    ):
        return False
    return any(k in output for k in keywords)


def extract_summary(output):
    """
    Extract a one-line summary of the vulnerability from the model output.
    """
    output = output.replace("\n", " ").replace("\r", " ").strip()
    lower = output.lower()

    if any(phrase in lower for phrase in general_phrase):
        return None

    match = re.search(r"1\.\s+(.*?)([.?!])", output)
    if match:
        return f"Possible vulnerability: {match.group(1).strip()}."

    match = re.match(r"^(.*?[.?!])(\s|$)", output)
    if match:
        return match.group(1).strip()

    return output[:150].strip() + "..." if len(output) > 150 else output


def extract_fix(output):
    # Try "Fix:" first
    match = re.search(r'fix[:\s-]+(.+?)([.?!]|$)', output, re.IGNORECASE)
    if match:
        return match.group(1).strip()

    # Try "suggested fix" as backup
    match = re.search(r'suggested fix[:\s-]+(.+?)([.?!]|$)', output, re.IGNORECASE)
    if match:
        return match.group(1).strip()

    return None


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
        print(f"\n Full analysis saved to: {filename}")
    except Exception as e:
        print(f"Error saving JSON: {e}")


def main():
    summary = " "
    results = []
    file_path = get_file_path_from_cli()  # Get file path from command line
    lines = read_file(file_path)  # Read the file content
    snippets = split_into_chunks(lines, chunk_size=10)  # Split into chunks of 10 lines

    for snippet_lines, line_start in snippets:
        # print(f"\n--- Analyzing lines {line_start}-{line_start + len(snippet_lines) - 1} ---")
        prompt = build_prompt(snippet_lines)  # Build the prompt for the Phi model
        output = query_phi_model(prompt)  # Query the Phi model with the prompt
        fix = extract_fix(output)  # Extract any fix suggestion from the output
        if is_vulnerability_detected(output):  # Check if the output indicates a vulnerability
            summary = extract_summary(output)
            if summary:
                print(f"⚠️ Line {line_start}: {summary}")  # Print the summary of the detected issue
                if fix:
                    print(f"🔧 Suggested Fix: {fix}")
            else:
                print(f"✅ Line {line_start}: No issue detected.")  # Print if no issue is detected
        else:
            print(f"✅ Line {line_start}: No issue detected.")

        # Store the results in a structured format
        results.append({
            "start_line": line_start,
            "end_line": line_start + len(snippet_lines) - 1,
            "summary": summary or "No issue detected.",
            "details": output.strip(),  # full LLM output
            "fix": fix or "No fix suggested."  # fix suggestion
        })

    export_to_json(results, filename="analysis_results.json")


# Run the main function if this script is executed directly
if __name__ == "__main__":
    main()
