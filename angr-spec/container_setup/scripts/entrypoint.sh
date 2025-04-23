#!/bin/sh

# Try to launch bash if it's executable, otherwise fall back to sh
if [ -x /bin/bash ]; then
  echo "✅ Launching bash..."
  exec /bin/bash
else
  echo "⚠️  Bash not available, falling back to sh..."
  exec /bin/sh
fi