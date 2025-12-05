apt-get update && apt-get install -y nano curl python3-pip nodejs npm xvfb
apt-get install -y apt-transport-https ca-certificates curl gnupg lsb-release
ollama pull nomic-embed-text

curl -LsSf https://astral.sh/uv/install.sh | sh
source $HOME/.local/bin/env
