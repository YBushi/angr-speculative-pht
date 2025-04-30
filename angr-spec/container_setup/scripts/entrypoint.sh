#!/bin/bash

# Activate virtualenv directly (no virtualenvwrapper)
VENV_PATH="$HOME/.virtualenvs/angr7"
if [ -f "$VENV_PATH/bin/activate" ]; then
  echo "✅ Activating virtualenv: angr7"
  source "$VENV_PATH/bin/activate"
else
  echo "❌ Virtualenv angr7 not found at $VENV_PATH"
fi

echo "✅ Launching bash..."
exec /bin/bash