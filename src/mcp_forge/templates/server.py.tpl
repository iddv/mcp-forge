from mcp.server.mcpserver import MCPServer

mcp = MCPServer("{{name}}", instructions="{{description}}", version="0.1.0")


@mcp.tool()
def hello(name: str) -> str:
    """Say hello to someone."""
    return f"Hello, {name}!"


def main():
    mcp.run()


if __name__ == "__main__":
    main()
