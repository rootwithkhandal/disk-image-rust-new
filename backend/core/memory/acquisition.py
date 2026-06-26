"""
Memory Acquisition Module
Wraps underlying memory dumping tools like WinPmem.
"""

import subprocess
import shutil
from pathlib import Path
from dataclasses import dataclass
from loguru import logger

@dataclass
class AcquisitionResult:
    success: bool
    dump_path: str = ""
    error: str = ""

class MemoryAcquisition:
    def __init__(self, tool_path: str = "winpmem"):
        """
        Initialize the memory acquisition wrapper.
        By default, it expects `winpmem` to be available in the system PATH.
        You can also pass an absolute path to the executable.
        """
        self.tool_path = tool_path

    def acquire(self, output_path: str) -> AcquisitionResult:
        """
        Executes the memory dumping tool to acquire RAM to the specified output_path.
        """
        if not shutil.which(self.tool_path) and not Path(self.tool_path).exists():
            return AcquisitionResult(
                success=False,
                error=f"Memory dumping tool '{self.tool_path}' not found. Please ensure it is in your PATH."
            )

        cmd = [self.tool_path, str(output_path)]
        try:
            logger.info(f"Starting memory acquisition: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
            
            if not Path(output_path).exists() or Path(output_path).stat().st_size == 0:
                error_msg = result.stderr.strip() or result.stdout.strip()
                # Try to get the last few lines of output for better error context
                lines = error_msg.splitlines()
                if len(lines) > 10:
                    error_msg = "\n".join(lines[-10:])
                return AcquisitionResult(
                    success=False,
                    error=f"Acquisition failed (return code {result.returncode}):\n{error_msg}"
                )

            return AcquisitionResult(
                success=True,
                dump_path=str(Path(output_path).absolute())
            )

        except subprocess.TimeoutExpired:
            return AcquisitionResult(
                success=False,
                error="Acquisition timed out after 30 minutes."
            )
        except Exception as e:
            return AcquisitionResult(
                success=False,
                error=f"Exception during acquisition: {e}"
            )
