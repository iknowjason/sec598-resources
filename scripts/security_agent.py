from mcp import StdioServerParameters
from InlineAgent.tools import MCPStdio
from InlineAgent.action_group import ActionGroup
from InlineAgent.agent import InlineAgent

server_params = StdioServerParameters(
    command="python3",
    args=["server_security_mcp.py"]
)

is_authorized = False

async def main():
    global is_authorized

    print("\n" + "=" * 80)
    print("SECURITY AUTHORIZATION REQUEST")
    print("=" * 80)
    target = input("Enter the target IP/hostname for security testing: ")

    auth_response = input(f"Do you have authorization to run security tests against {target}? (yes/no): ").lower()
    if auth_response == "yes":
        is_authorized = True
        print("Authorization confirmed.")
        # Pass the authorization status to the server via an environment variable
        server_params.env = server_params.env or {}
        server_params.env["SECURITY_AUTHORIZED"] = "true"
        server_params.env["SECURITY_TARGET"] = target
    else:
        is_authorized = False
        print("Authorization denied. Security testing cannot proceed.")
        return


    security_mcp_client = await MCPStdio.create(server_params=server_params)
    try:
        security_testing_action_group = ActionGroup(
            name="SecurityTestingActionGroup",
            description="Helps to perform the full lifecycle of security testing against a target.",
            mcp_clients=[security_mcp_client],
        )

        await InlineAgent(
            foundation_model="us.anthropic.claude-3-5-sonnet-20241022-v2:0",
            #foundation_model="us.meta.llama3-1-70b-instruct-v1:0",
            #foundation_model="us.deepseek.r1-v1:0",
            instruction="""You are a Cyber Security expert helping to perform automated penetration testing, to simulate an adversary. You will follow these exact instructions in order:
            
            1. First, get the methodology which outlines the security testing steps.            
            2. Test accessing the Amazon EC2 Linux instance using Amazon SSM API commands with aws cli.
            3. Decide which security tool needs to run based on the results.
            4. Run the security tool with the target IP address and any other parameters needed.
            5. Keep performing security testing with each run_tool_TOOL_NAME until the final phase of the methodology is achieved, or the user says to stop running security tools.

            """,
            agent_name="security_testing_agent",
            action_groups=[security_testing_action_group],
        ).invoke(
            input_text=f"Perform security testing against {target}."
        )
    finally:
        await security_mcp_client.cleanup()


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())