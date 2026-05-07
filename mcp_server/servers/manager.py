import os
import requests
from fastmcp import FastMCP
from langchain.tools import tool
from dotenv import load_dotenv


load_dotenv()

GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
ORCHESTRATION_URL = os.getenv("ORCHESTRATION_URL", "http://44.208.103.127:8000")
GITHUB_API_URL = "https://api.github.com"

manager_server = FastMCP('Manager')


@manager_server.tool
def accept_pr(repo_full_name: str, pr_number: int, merge_method: str = "merge") -> dict:
    """
    Merge a pull request that has passed security analysis.

    Only call this tool after security analysis has completed successfully and
    no vulnerabilities were found. Do not call if analysis failed or is pending.

    Args:
        repo_full_name: Full repository name in "owner/repo" format (e.g. "acme/backend").
        pr_number: The pull request number to merge.
        merge_method: Strategy used to merge the PR. One of "merge", "squash", or "rebase".
                      Defaults to "merge".

    Returns:
        dict: GitHub API response on success, e.g. {"sha": "...", "merged": True, "message": "..."}.
              On failure: {"success": False, "error": "<error message>"}.
    """
    if merge_method not in ('merge', 'squash', 'rebase'):
        raise ValueError('merge_method must be "merge", "squash", or "rebase"')
    
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        raise ValueError("GITHUB_TOKEN environment variable not set")
    
    # Split repo_full_name into owner/repo
    owner, repo = repo_full_name.split("/", 1)
    
    url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/merge"
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    payload = {"merge_method": merge_method}

    try:
        response = requests.put(url, headers=headers, json=payload)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        return {"success": False, "error": str(e)}


@manager_server.tool
def send_pr_notification(message: str = ""):
    """
    Send a Slack notification about a merged pull request.

    Posts a message to the configured Slack channel using the SLACK_BOT_TOKEN
    and SLACK_CHANNEL environment variables.

    Args:
        message: The message text to post to Slack.

    Returns:
        dict: Slack API response on success, e.g. {"ok": True, "channel": "...", "ts": "..."}.
              On failure: {"ok": False, "error": "<error message>"}.
    """
    print('send pr message tool was called')
    slack_app_token = os.getenv("SLACK_BOT_TOKEN", "")
    url = "https://slack.com/api/chat.postMessage"
    headers = {
        "Authorization": f"Bearer {slack_app_token}",
        "Content-Type": "application/json"
    }
    channel = os.getenv("SLACK_CHANNEL", "")
    payload = {
        "channel": channel,
        "text": message
    }
    try:
        response = requests.post(url, headers=headers, json=payload)
        print('aparently, message was sent')
        print(f'message sent: {message}')
        response.raise_for_status()

        return response.json()
    except Exception as e:
        return f"Error sending pr notification: {e}"
