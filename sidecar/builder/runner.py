import os
import subprocess
import shutil
import typing
from pathlib import Path
from pydantic import BaseModel

AGENTARMOR_DIR = Path.home() / ".agentarmor"

# Keep track of running agent processes
_running_agents: typing.Dict[str, typing.Dict[str, typing.Any]] = {}

def _spawn_process(agent_id: str, workspace: Path):
    """Helper to spawn the uv run process for an agent."""
    try:
        log_file = open(workspace / "agent.log", "a", encoding="utf-8")
        
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUTF8"] = "1"
        
        proc = subprocess.Popen(
            ["uv", "run", "agent.py"],
            cwd=str(workspace),
            stdout=log_file,
            stderr=subprocess.STDOUT,
            shell=False,
            env=env,
        )
        
        _running_agents[agent_id] = {
            "process": proc,
            "workspace": str(workspace),
            "log_file": log_file
        }
        return True
    except Exception as e:
        print(f"Failed to spawn agent {agent_id}: {e}")
        return False

def deploy_agent(agent_id: str, script_content: str) -> bool:
    """
    Deploys and runs an agent script using `uv run`.
    Creates a dedicated workspace directory for the agent.
    """
    agents_dir = AGENTARMOR_DIR / "agents"
    agents_dir.mkdir(parents=True, exist_ok=True)
    
    workspace = agents_dir / agent_id
    
    # If it already exists, clear it
    if workspace.exists():
        shutil.rmtree(workspace)
        
    workspace.mkdir(parents=True)
    
    # Save the script
    script_path = workspace / "agent.py"
    script_path.write_text(script_content, encoding="utf-8")
    
    return _spawn_process(agent_id, workspace)

def resume_all_agents():
    """Finds all agents with workspaces and re-spawns them."""
    agents_dir = AGENTARMOR_DIR / "agents"
    if not agents_dir.exists():
        return
        
    for agent_dir in agents_dir.iterdir():
        if agent_dir.is_dir() and (agent_dir / "agent.py").exists():
            agent_id = agent_dir.name
            if agent_id not in _running_agents:
                print(f"Resuming agent: {agent_id}")
                _spawn_process(agent_id, agent_dir)

def kill_agent(agent_id: str):
    if agent_id in _running_agents:
        proc = _running_agents[agent_id]["process"]
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except Exception:
            proc.kill()
        
        try:
            _running_agents[agent_id]["log_file"].close()
        except:
            pass
            
        del _running_agents[agent_id]
        return True
    return False

def get_running_agents():
    return list(_running_agents.keys())
