#!/usr/bin/env bash
# Launch VAPTBench with sane defaults. Edit the exports to taste.
cd "$(dirname "$0")"
[ -d .venv ] && source .venv/bin/activate

export VAPT_OLLAMA_URL="${VAPT_OLLAMA_URL:-http://localhost:11434}"
export VAPT_OLLAMA_MODEL="${VAPT_OLLAMA_MODEL:-qwen3:14b}"
export VAPT_WORDLIST="${VAPT_WORDLIST:-/usr/share/seclists/Discovery/Web-Content/common.txt}"
# Hybrid AI (optional): uncomment to route tasks to the cloud instead.
# export VAPT_AI_BACKEND=cloud
# export VAPT_CLOUD_KEY=sk-ant-...

exec python app.py
