import argparse
import subprocess

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
            print(f"Content of {file_path}:\n")
            print(content)
            return content
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return []



def split_into_chunks(lines, chunk_size=10):
    """
    Splits the list of lines into chunks of a specified size and prints each chunk.
    :param lines:
    :param chunk_size:
    :return:
    """
    chunk_arr = []
    for i in range(0, len(lines), chunk_size):
        chunk = lines[i:i + chunk_size]
        chunk_arr.append((chunk, i+1))
        print(f"Chunk {i // chunk_size + 1}:\n{chunk}\n")

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
            input = prompt.encode(),
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
    keywords = ["volnerability", "buffer overflow", "uninitialized variable", "memory leak",
                "corruption", "security issue", ""
                                                                                                                             "use after free",
                "dangling"]
    return any(k in output.lower() for k in keywords)

def extract_summary(output):
    """
    Extract a summary from the output of the Phi model.
    :param output:
    :return:
    """
    # This is a simple implementation; you may want to improve it based on your needs.
    lines = output.strip().splitlines()
    for line in lines:
        if any(k in line.lower() for k in ["overflow", "use-after-free", "vulnerability"]):
            return line.strip()
        # Fallback if no match found
        return output.strip()[:100] + "..." if output.strip() else "[No summary]"


def main():
    file_path = get_file_path_from_cli()
    lines = read_file(file_path)
    snippets = split_into_chunks(lines, chunk_size=10)

    for snippet_lines, line_start in snippets:
        print(f"\n--- Analyzing lines {line_start}-{line_start + len(snippet_lines) - 1} ---")
        prompt = build_prompt(snippet_lines)
        output = query_phi_model(prompt)
        if is_vulnerability_detected(output):
            summary = extract_summary(output)
            print(f"⚠️  Line {line_start}: {summary}")
        else:
            print("✅ No issue detected.")




if __name__ == "__main__":
    main()
