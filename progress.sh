#!/bin/bash
# progress.sh - MCP-Forge Project Progress Viewer
# Displays progress information from progress_data.json in a nicely formatted view

echo "Generating MCP-Forge Progress Report..."
cat progress_data.json | jq -r 'to_entries | sort_by(.key | split(":") | .[0] | tonumber) | group_by(.key | split(":") | .[0]) | map({"phase": (.[0].key | split(":") | .[0]), "tasks": map({"name": (.key | split(":") | .[1]), "status": .value.status, "updated": (.value.last_updated // "Unknown date"), "completed": (.value.status == "Completed")}), "completed_count": map(select(.value.status == "Completed")) | length, "total_count": length}) | "MCP-FORGE PROJECT SUMMARY\n=====================\nTotal tasks: \(map(.total_count) | add)\nCompleted: \(map(.completed_count) | add)\nProgress: \((map(.completed_count) | add) * 100 / (map(.total_count) | add) | floor)%\n\n" + (map("Phase \(.phase) (\(.completed_count)/\(.total_count) complete):\n\(.tasks | sort_by(.completed | not) | map("  \(if .completed then "✅" else "⬜️" end) \(.name): \(.status) (\(.updated | sub("T.*"; "")))") | join("\n"))\n") | join(""))'

echo -e "\nProgress report complete. To update progress, use: python3 progress_tracker.py update <phase> \"<task>\" \"<status>\" --notes \"<notes>\"" 