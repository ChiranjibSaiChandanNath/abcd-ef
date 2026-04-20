import docker
import os
import logging
import platform

logger = logging.getLogger(__name__)

def run_docker_sandbox(file_path: str, filename: str) -> dict:
    """
    Run file inside isolated Docker container and capture behavior.
    Returns dict with sandbox results.
    """
    results = {
        "sandbox_used": True,
        "file_info": "",
        "suspicious_strings": [],
        "dynamic_logs": [],
        "hex_header": "",
        "error": None,
        "raw_output": ""
    }

    if not os.path.exists(file_path):
        results["error"] = "File not found"
        return results

    try:
        client = docker.from_env()

        # Run the sandbox container
        file_dir  = os.path.dirname(os.path.abspath(file_path))
        file_name = os.path.basename(file_path)

        output = client.containers.run(
            image="malware-sandbox",
            command=f"/sandbox/run_analysis.sh /target/{file_name}",
            volumes={
                file_dir: {"bind": "/target", "mode": "ro"}
            },
            network_disabled=True,       # NO internet
            mem_limit="256m",            # max RAM
            cpu_quota=50000,             # max 50% CPU
            cpu_period=100000,
            remove=True,                 # auto-delete after run
            stdout=True,
            stderr=True,
            timeout=20,
        )

        raw = output.decode("utf-8", errors="ignore")
        results["raw_output"] = raw

        # Parse sections
        lines = raw.splitlines()
        current_section = None
        susp_strings = []
        dynamic_logs = []

        for line in lines:
            if "[1] FILE INFORMATION" in line:
                current_section = "file_info"
            elif "[4] SUSPICIOUS STRINGS" in line:
                current_section = "suspicious"
            elif "[7] DYNAMIC EXECUTION" in line:
                current_section = "dynamic"
            elif "[6] HEX HEADER" in line:
                current_section = "hex"
            elif line.startswith("=== ["):
                current_section = "other"
            elif current_section == "file_info" and line.strip() and not line.startswith("==="):
                if not results["file_info"]:
                    results["file_info"] = line.strip()
            elif current_section == "suspicious" and line.strip() and not line.startswith("==="):
                susp_strings.append(line.strip())
            elif current_section == "dynamic" and line.strip() and not line.startswith("==="):
                dynamic_logs.append(line.strip())
            elif current_section == "hex" and line.strip() and not line.startswith("==="):
                if not results.get("hex_header"):
                    results["hex_header"] = line.strip()

        results["suspicious_strings"] = susp_strings[:20]
        results["dynamic_logs"] = dynamic_logs[:30]

    except docker.errors.ImageNotFound:
        results["error"] = "Sandbox image not built. Ensure 'docker build -t malware-sandbox ./sandbox/' is run."
    except docker.errors.DockerException as e:
        results["error"] = f"Docker error: {str(e)}"
    except Exception as e:
        logger.exception(f"Sandbox error: {e}")
        results["error"] = str(e)

    return results
