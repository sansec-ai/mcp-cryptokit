import asyncio

from mcp.server.models import InitializationOptions
import mcp.types as types
from mcp.server import NotificationOptions, Server
from pydantic import AnyUrl
import mcp.server.stdio
import crypto_utils

NWS_API_BASE = "https://api.cryptokit.gov"
USER_AGENT = " CryptoKit-app/1.0"

notes: dict[str, str] = {}

server = Server("crypto")

@server.list_resources()
async def handle_list_resources() -> list[types.Resource]:
    return None
    """
    List available crypto resources.
    """
    return [
        types.Resource(
            uri=AnyUrl(f"crypto://internal/{name}"),
            name=f"Crypto: {name}",
            description=f"A crypto resource named {name}",
            mimeType="text/plain",
        )
        for name in ["aes", "rsa", "hash"]
    ]

@server.read_resource()
async def handle_read_resource(uri: AnyUrl) -> str:
    return None
    """
    Read a specific note's content by its URI.
    The note name is extracted from the URI host component.
    """
    if uri.scheme != "note":
        raise ValueError(f"Unsupported URI scheme: {uri.scheme}")

    name = uri.path
    if name is not None:
        name = name.lstrip("/")
        return notes[name]
    raise ValueError(f"Note not found: {name}")

@server.list_prompts()
async def handle_list_prompts() -> list[types.Prompt]:
    return None
    """
    List available prompts.
    Each prompt can have optional arguments to customize its behavior.
    """
    return [
        types.Prompt(
            name="summarize-notes",
            description="Creates a summary of all notes",
            arguments=[
                types.PromptArgument(
                    name="style",
                    description="Style of the summary (brief/detailed)",
                    required=False,
                )
            ],
        )
    ]

@server.get_prompt()
async def handle_get_prompt(
    name: str, arguments: dict[str, str] | None
) -> types.GetPromptResult:
    return None
    """
    Generate a prompt by combining arguments with server state.
    The prompt includes all current notes and can be customized via arguments.
    """
    # if name != "summarize-notes":
    #     raise ValueError(f"Unknown prompt: {name}")

    # style = (arguments or {}).get("style", "brief")
    # detail_prompt = " Give extensive details." if style == "detailed" else ""

    # return types.GetPromptResult(
    #     description="Summarize the current notes",
    #     messages=[
    #         types.PromptMessage(
    #             role="user",
    #             content=types.TextContent(
    #                 type="text",
    #                 text=f"Here are the current notes to summarize:{detail_prompt}\n\n"
    #                 + "\n".join(
    #                     f"- {name}: {content}"
    #                     for name, content in notes.items()
    #                 ),
    #             ),
    #         )
    #     ],
    # )

@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """
    List available crypto tools.
    """
    return [
        types.Tool(
            name="aes-encrypt",
            description="AES对称加密",
            inputSchema={
                "type": "object",
                "properties": {
                    "plaintext": {"type": "string", "description": "待加密文本"},
                    "key": {"type": "string", "description": "加密密钥"},
                },
                "required": ["plaintext", "key"],
            },
        ),
        types.Tool(
            name="aes-decrypt",
            description="AES对称解密",
            inputSchema={
                "type": "object",
                "properties": {
                    "ciphertext": {"type": "string", "description": "待解密文本"},
                    "key": {"type": "string", "description": "解密密钥"},
                },
                "required": ["ciphertext", "key"],
            },
        ),
        types.Tool(
            name="rsa-encrypt",
            description="RSA非对称加密",
            inputSchema={
                "type": "object",
                "properties": {
                    "plaintext": {"type": "string", "description": "待加密文本"},
                    "public_key": {"type": "string", "description": "公钥"},
                },
                "required": ["plaintext", "public_key"],
            },
        ),
        types.Tool(
            name="rsa-decrypt",
            description="RSA非对称解密",
            inputSchema={
                "type": "object",
                "properties": {
                    "ciphertext": {"type": "string", "description": "待解密文本"},
                    "private_key": {"type": "string", "description": "私钥"},
                },
                "required": ["ciphertext", "private_key"],
            },
        ),
        types.Tool(
            name="hash",
            description="Hash算法",
            inputSchema={
                "type": "object",
                "properties": {
                    "algorithm": {"type": "string", "description": "算法类型（md5/sha256等）"},
                    "data": {"type": "string", "description": "待哈希数据"},
                },
                "required": ["algorithm", "data"],
            },
        ),
    ]

@server.call_tool()
async def handle_call_tool(
    name: str, arguments: dict | None
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    """
    Handle crypto tool execution requests.
    """
    if not arguments:
        raise ValueError("Missing arguments")

    try:
        if name == "aes-encrypt":
            # Implement AES encryption        
            result = crypto_utils.aes_encrypt(
                    arguments["plaintext"],
                    arguments["key"]
                )
        elif name == "aes-decrypt":
            # Implement AES decryption
            result = crypto_utils.aes_decrypt(
                    arguments["ciphertext"],
                    arguments["key"]
                )
        elif name == "rsa-encrypt":
            # Implement RSA encryption
            result = crypto_utils.rsa_encrypt(
                    arguments["plaintext"],
                    arguments["public_key"]
                )
        elif name == "rsa-decrypt":
            # Implement RSA decryption
            result = crypto_utils.rsa_decrypt(
                    arguments["ciphertext"],
                    arguments["private_key"]
                )
        elif name == "hash":
            # Implement hash function
            result = crypto_utils.hash_data(
                    arguments["algorithm"],
                    arguments["data"]
                )
        else:
            raise ValueError(f"Unknown tool: {name}")
        return [types.TextContent(type="text", text=result)]
    except KeyError as e:
        raise ValueError(f"Missing required parameter: {e}")
    except Exception as e:
        raise ValueError(f"Operation failed: {str(e)}")

async def main():
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name=" CryptoKit",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )

if __name__ == "__main__":
    asyncio.run(main())