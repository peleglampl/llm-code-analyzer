# 🔍 Security Vulnerability Scanner – Report

## Overview
This tool analyzes C/C++ files using a local LLM (via Ollama) to detect real security vulnerabilities and suggest fixes, chunk by chunk.

## Why LLM? 
LLMs can understand code context and explain issues in natural language. Using a local model ensures privacy and keeps the tool usable offline.

## Design Highlights
- **Chunking**: Breaks files into manageable pieces to fit LLM input limits.
- **Prompting**: Uses a structured prompt to guide the LLM in identifying vulnerabilities.
- **Filtering**: Discards generic or unhelpful responses to focus on actionable insights.
- **Output**: Provides both CLI output and structured JSON for easy integration with other tools.
- **Fix Suggestions**: Where applicable, suggests one-line fixes for identified issues.

## Challenges
🛑 **Docker**: Attempted containerization with Ollama but faced socket and model access issues on Windows. Skipped for simplicity.

⚠️ **LLM Limitations**: Required extra filtering to avoid noisy or non-informative output.

## Summary
The project focuses on clean code, prompt engineering, and reliability over flashy UI. The LLM was guided precisely to reduce false positives and output meaningful suggestions.