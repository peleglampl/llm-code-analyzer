LLM-Powered Vulnerability Scanner for C/C++ Code

Description:

This tool scans C and C++ code for potential security vulnerabilities using the Phi LLM (via Ollama). It splits the source code into chunks, sends them to the model, and reports real vulnerabilities along with suggested one-line fixes.

Features:
- Scans .c, .cpp, .h, .hpp files

- Uses chunking for LLM scalability (configurable)

- Filters out generic, speculative, or unhelpful LLM responses

- Suggests fixes where applicable

- Outputs results as readable CLI output and structured JSON

Requirements:
- Python 3.8+

- Ollama installed and running locally with phi model

Usage:

python analyzer.py path/to/code.c  10

Where:
- Replace 10 with the number of lines per chunk.
- Replace path/to/code.c with the path to your C/C++ source file.

Output:
- CLI output with vulnerabilities and fixes
- JSON file with structured results as 'analyzer_results.json'

Limitations:
- Requires Ollama to be running locally

- Cannot catch vulnerabilities that require full context or cross-chunk analysis

- Model output may still require human review

Example command:
ollama run phi
python analyzer.py path/to/code.c 10