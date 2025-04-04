# MCP Server Template System

The Template System provides a flexible framework for generating customized MCP servers based on templates. This enables the Meta-MCP Server to dynamically create child servers with various capabilities and configurations.

## Components

### 1. Template Manager

The `TemplateProcessor` class handles loading, parsing, and generating MCP server scripts from templates. It ensures that all required placeholders are properly replaced with actual values.

Usage example:

```python
from template_system import get_template_manager
from template_system.templates import get_base_template_path

# Get the template manager with the base template
template_manager = get_template_manager(get_base_template_path())

# Generate a server script
template_manager.generate_server(
    output_path="./servers/my_server.py",
    server_name="My Server",
    server_port=9001,
    description="My custom MCP server",
    capabilities=["echo", "time", "uptime"]
)
```

### 2. Template Validator

The `TemplateValidator` class ensures that templates contain all required placeholders and are syntactically valid. It also validates capabilities to ensure they meet the required format.

Usage example:

```python
from template_system import TemplateValidator

# Validate a template file
is_valid, error_message = TemplateValidator.validate_template_file("./templates/my_template.py")
if not is_valid:
    print(f"Template validation failed: {error_message}")

# Validate capabilities
is_valid, error_message = TemplateValidator.validate_capabilities(["echo", "time", "custom-capability"])
if not is_valid:
    print(f"Capability validation failed: {error_message}")
```

### 3. Template Customizer

The `TemplateCustomizer` class enables adding additional handlers and server options to a template. It provides a way to extend the base functionality of an MCP server.

Usage example:

```python
from template_system import TemplateCustomizer

# Create a customizer
customizer = TemplateCustomizer()

# Get available customization options
options = customizer.get_available_customizations()
print(f"Available handlers: {list(options['handlers'].keys())}")
print(f"Available server options: {list(options['server_options'].keys())}")

# Customize a template
with open("./templates/my_template.py", "r") as f:
    template_content = f.read()

customized_content = customizer.customize_template(
    template_content=template_content,
    handlers=["file_reader", "http_request"],
    options={
        "persistence": "sqlite",
        "auth": "basic",
        "logging": "detailed"
    }
)

with open("./servers/my_customized_server.py", "w") as f:
    f.write(customized_content)
```

## Template Format

Templates should be Python files with the following placeholders:

- `{{SERVER_NAME}}`: Name of the server
- `{{SERVER_DESCRIPTION}}`: Description of the server
- `{{SERVER_PORT}}`: Port the server will listen on
- `{{SERVER_CAPABILITIES}}`: JSON list of capabilities
- `{{SERVER_HANDLERS}}`: JSON mapping of capability names to handler functions

Example:

```python
# Configurable parameters (will be replaced by the meta-server)
SERVER_NAME = "{{SERVER_NAME}}"
SERVER_DESCRIPTION = "{{SERVER_DESCRIPTION}}"
SERVER_PORT = {{SERVER_PORT}}
SERVER_CAPABILITIES = {{SERVER_CAPABILITIES}}
SERVER_HANDLERS = {{SERVER_HANDLERS}}
```

## Available Handlers

The template system includes several pre-defined handlers that can be added to servers:

1. **File Reader** (`file_reader`): Reads files from the server's filesystem
2. **HTTP Request** (`http_request`): Makes HTTP requests to external services
3. **Database** (`database`): Provides simple database functionality with SQLite

## Server Options

The following server options can be configured:

1. **Persistence** (`persistence`):
   - `memory`: In-memory storage (default)
   - `file`: File-based storage
   - `sqlite`: SQLite database storage

2. **Authentication** (`auth`):
   - `none`: No authentication (default)
   - `basic`: Basic username/password authentication
   - `token`: Token-based authentication

3. **Logging** (`logging`):
   - `basic`: Basic logging (default)
   - `detailed`: Detailed logging with more information
   - `debug`: Debug-level logging with maximum information 