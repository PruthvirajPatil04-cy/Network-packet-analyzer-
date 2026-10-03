import asyncio
import os
from google.antigravity import Agent, LocalAgentConfig

async def main() -> None:
    """Initialize agent and ask a basic network security question."""
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("Error: GEMINI_API_KEY environment variable is not set.")
        return
        
    config = LocalAgentConfig(
        system_instructions="You are a network security expert.",
        api_key=api_key
    )
    async with Agent(config) as agent:
        response = await agent.chat("In one sentence, what is packets-per-second (PPS)?")
        print(await response.text())

if __name__ == "__main__":
    asyncio.run(main())
