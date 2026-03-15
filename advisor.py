import os
import logging
import asyncio
import json
import urllib.request
import yaml
from telegram import Update
from telegram.ext import ApplicationBuilder, ContextTypes, MessageHandler, filters
from langchain_ollama import ChatOllama
from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
from langgraph.graph import START, END, StateGraph
from langgraph.prebuilt import ToolNode, tools_condition

# Load .env file if present
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# --- LOGGING ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("advisor.log"),
    ],
)
log = logging.getLogger("advisor")

# --- CONFIGURATION ---
TOKEN = os.environ["TELEGRAM_BOT_TOKEN"]
MY_ID = int(os.environ["TELEGRAM_USER_ID"])
MODEL = os.getenv("OLLAMA_MODEL", "MichelRosselli/GLM-4.5-Air")

_base_dir = os.path.dirname(os.path.abspath(__file__))


# --- FLEET LOADING ---
def _load_fleet(path: str) -> dict[str, dict]:
    """
    Load hosts.yaml and return a dict keyed by host name.
    Indexer passwords are resolved from environment variables at startup
    so a missing secret crashes loudly here rather than silently mid-conversation.
    """
    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    fleet: dict[str, dict] = {}
    for entry in raw.get("hosts", []):
        name = entry["name"]
        pw_env = entry.get("indexer_password_env")
        if pw_env:
            pw = os.environ.get(pw_env)
            if not pw:
                raise EnvironmentError(
                    f"Host '{name}' requires env var '{pw_env}' but it is not set. "
                    f"Add it to your .env file."
                )
            entry["indexer_password"] = pw
        fleet[name] = entry
    return fleet


_hosts_path = os.path.join(_base_dir, "hosts.yaml")
FLEET: dict[str, dict] = _load_fleet(_hosts_path)
log.info("Fleet loaded: %s", list(FLEET.keys()))

# Inject fleet into tools module so every @tool can resolve host names
import tools as _tools_module
_tools_module.FLEET = FLEET


# --- SSH KEY PERMISSION CHECK ---
from ssh_client import check_key_permissions, close_all as _ssh_close_all
check_key_permissions(FLEET)


# --- LOAD SKILL PROMPT ---
_skills_path = os.path.join(_base_dir, "skills.md")
try:
    with open(_skills_path, "r", encoding="utf-8") as f:
        _raw_skills = f.read()
except FileNotFoundError:
    log.error("skills.md not found at %s — aborting.", _skills_path)
    raise


def _build_system_prompt(fleet: dict[str, dict], skills_text: str) -> str:
    """Append a dynamic host roster to the static skills prompt."""
    lines = ["\n\n---\n\n## Available Wazuh Hosts\n"]
    lines.append(
        "You MUST pass the `host` argument in every tool call. "
        "Choose from the list below. If the user's message does not clearly "
        "identify a host, ask them to clarify before calling any tool. "
        "Never guess or fabricate a host name.\n"
    )
    for name, cfg in fleet.items():
        tags = ", ".join(cfg.get("tags", [])) or "—"
        lines.append(f"- `{name}` — {cfg['hostname']}  tags: [{tags}]")
    return skills_text + "\n".join(lines)


SOP = _build_system_prompt(FLEET, _raw_skills)


# --- STARTUP HEALTH CHECK ---
def _check_ollama() -> None:
    """Verify Ollama is reachable and the configured model is available."""
    ollama_host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    url = f"{ollama_host}/api/tags"
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            tags = json.loads(resp.read())
        models = [m.get("name", "") for m in tags.get("models", [])]
        if not any(MODEL in m for m in models):
            log.warning("Model '%s' not found in Ollama. Available: %s", MODEL, models)
            log.warning("Run: ollama pull %s", MODEL)
    except Exception as e:
        log.warning("Ollama health check failed: %s", e)


# --- TOOLS & GRAPH SETUP ---
from tools import (
    audit_os_resources,
    validate_wazuh_config,
    check_wazuh_daemons,
    audit_wazuh_networking,
    check_indexer_health,
    search_wazuh_errors,
)

tools = [
    audit_os_resources,
    validate_wazuh_config,
    check_wazuh_daemons,
    audit_wazuh_networking,
    check_indexer_health,
    search_wazuh_errors,
]

llm = ChatOllama(model=MODEL, temperature=0).bind_tools(tools)


def call_model(state):
    messages = [SystemMessage(content=SOP)] + state["messages"]
    response = llm.invoke(messages)
    return {"messages": [response]}


workflow = StateGraph(dict)
workflow.add_node("agent", call_model)
workflow.add_node("tools", ToolNode(tools))
workflow.add_edge(START, "agent")
workflow.add_conditional_edges("agent", tools_condition)
workflow.add_edge("tools", "agent")

_db_path = os.path.join(_base_dir, "advisor.db")
app_graph = None  # initialized in main()


# --- TELEGRAM HANDLER ---
async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not update.message:
        return
    user_id = update.effective_user.id
    if user_id != MY_ID:
        log.warning("Rejected message from unauthorized user ID: %s", user_id)
        return

    chat_id = str(update.effective_chat.id)
    user_input = update.message.text
    log.info("Received message from %s (chat %s)", user_id, chat_id)

    config = {"configurable": {"thread_id": chat_id}}

    try:
        await update.message.reply_text("Checking now, this may take a moment...")
        await update.message.reply_chat_action("typing")
        result = await asyncio.wait_for(
            app_graph.ainvoke({"messages": [HumanMessage(content=user_input)]}, config),
            timeout=120,
        )
        reply = result["messages"][-1].content
        if len(reply) > 4096:
            reply = reply[:4090] + "\n[…]"
        await update.message.reply_text(reply)
    except asyncio.TimeoutError:
        log.error("Graph invocation timed out for chat %s", chat_id)
        await update.message.reply_text("Request timed out. The LLM or a tool took too long.")
    except Exception as e:
        log.exception("Unhandled error in handle_message for chat %s", chat_id)
        await update.message.reply_text(f"An error occurred: {type(e).__name__}")


if __name__ == "__main__":
    async def main():
        global app_graph
        _check_ollama()
        log.info("Wazuh Advisor starting — model: %s | fleet: %s", MODEL, list(FLEET.keys()))
        async with AsyncSqliteSaver.from_conn_string(_db_path) as memory:
            app_graph = workflow.compile(checkpointer=memory)
            application = ApplicationBuilder().token(TOKEN).build()
            application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
            async with application:
                await application.start()
                await application.updater.start_polling()
                try:
                    await asyncio.Event().wait()
                except asyncio.CancelledError:
                    pass
                finally:
                    await application.updater.stop()
                    await application.stop()

    try:
        asyncio.run(main())
    finally:
        _ssh_close_all()
