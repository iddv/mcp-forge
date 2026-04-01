[project]
name = "{{name}}"
version = "0.1.0"
description = "{{description}}"
requires-python = ">=3.10"
dependencies = [
    "mcp[cli]>=1.6.0",
]

[project.optional-dependencies]
test = [
    "pytest>=7.0.0",
    "anyio>=4.0.0",
    "pytest-anyio>=0.0.0",
]

[project.scripts]
{{name}} = "server:main"

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"
