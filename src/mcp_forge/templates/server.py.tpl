from mcp.server.fastmcp import FastMCP

mcp = FastMCP("{{name}}", description="{{description}}")


@mcp.tool()
def hello(name: str) -> str:
    """Say hello to someone."""
    return f"Hello, {name}!"


def main():
    mcp.run()


if __name__ == "__main__":
    main()
