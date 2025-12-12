#!/usr/bin/env python3
"""
Wrapper script to ensure dependencies are installed before running the server.
This is needed when the server is packaged with mcpb pack.
"""
import sys
import site
import subprocess
import os
from pathlib import Path
from mcp.server.fastmcp import FastMCP

# CRITICAL: Add user site-packages to sys.path FIRST, before any other imports
# This ensures we can find packages installed with --user flag
user_site = site.getusersitepackages()
if user_site and user_site not in sys.path:
    sys.path.insert(0, user_site)
# Also add site.USER_SITE if different
try:
    if hasattr(site, 'USER_SITE') and site.USER_SITE and site.USER_SITE not in sys.path:
        sys.path.insert(0, site.USER_SITE)
except:
    pass

def check_and_install_dependencies():
    """Check if dependencies are installed, install if needed."""
    try:
        import mcp
        # Dependencies are already installed
        return
    except ImportError:
        # Dependencies not installed, need to install them
        script_dir = Path(__file__).parent
        project_root = script_dir.parent
        requirements_file = project_root / "requirements.txt"
        pyproject_file = project_root / "pyproject.toml"

        # Try to install from requirements.txt first
        if requirements_file.exists():
            print("Installing dependencies from requirements.txt...", file=sys.stderr)
            subprocess.check_call([
                sys.executable, "-m", "pip", "install", "--user", "--quiet",
                "--no-warn-script-location",
                "-r", str(requirements_file)
            ], stderr=subprocess.DEVNULL)
        elif pyproject_file.exists():
            print("Installing dependencies from pyproject.toml...", file=sys.stderr)
            subprocess.check_call([
                sys.executable, "-m", "pip", "install", "--user", "--quiet",
                "--no-warn-script-location",
                str(project_root)
            ], stderr=subprocess.DEVNULL)
        else:
            print("Warning: No requirements.txt or pyproject.toml found", file=sys.stderr)
            return

        # Force reload of site-packages after installation
        import importlib
        importlib.reload(site)

        # Re-add user site-packages after installation (may have changed)
        user_site = site.getusersitepackages()
        if user_site:
            # Add both the site-packages directory and its parent
            if user_site not in sys.path:
                sys.path.insert(0, user_site)
            # Also add the parent directory in case packages are installed there
            user_site_parent = str(Path(user_site).parent)
            if user_site_parent not in sys.path:
                sys.path.insert(0, user_site_parent)

        # Verify installation worked - try importing with a fresh import
        import importlib.util
        try:
            # Force a fresh import
            if 'mcp' in sys.modules:
                del sys.modules['mcp']
            import mcp
        except ImportError:
            # Try one more time after a brief moment
            import time
            time.sleep(0.1)
            try:
                import mcp
            except ImportError:
                print("Error: Failed to install dependencies. Please install manually:", file=sys.stderr)
                if requirements_file.exists():
                    print(f"  {sys.executable} -m pip install --user -r {requirements_file}", file=sys.stderr)
                sys.exit(1)

if __name__ == "__main__":
    # Check and install dependencies if needed
    check_and_install_dependencies()

    # Ensure user site-packages is definitely in path
    user_site = site.getusersitepackages()
    if user_site and user_site not in sys.path:
        sys.path.insert(0, user_site)

    # Change to server directory
    script_dir = Path(__file__).parent
    os.chdir(script_dir)
    main_script = script_dir / "main.py"

    # Add server directory to path so imports work
    if str(script_dir) not in sys.path:
        sys.path.insert(0, str(script_dir))

    # Use runpy to execute main.py as __main__
    # This properly handles __name__ == "__main__" and preserves sys.argv
    import runpy
    # Preserve original argv but set script name
    original_argv = sys.argv[:]
    sys.argv = [str(main_script)] + sys.argv[1:]
    try:
        runpy.run_path(str(main_script), run_name="__main__")
    finally:
        sys.argv = original_argv
