#!/bin/sh

# Set default command if none provided
COMMAND=${1:-generate_attestation}

shift

# Filter out empty arguments
filtered_args=""
for arg in "$@"; do
  if [ -n "$arg" ] && [ "$arg" != '""' ] && [ "$arg" != "''" ]; then
    if [ -z "$filtered_args" ]; then
      filtered_args="$arg"
    else
      filtered_args="$filtered_args $arg"
    fi
  fi
done

echo "Command: $COMMAND"
echo "Filtered args: $filtered_args"

case "${COMMAND}" in
  "generate_attestation")
    exec /app/generate-attestation "$filtered_args"
    ;;
  "verify_attestation")
    exec /app/verify-attestation "$filtered_args"
    ;;
  *)
    echo "Unknown command: ${COMMAND}"
    echo "Available commands: generate_attestation, verify_attestation"
    exit 1
    ;;
esac
